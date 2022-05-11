import { KMSClient, CreateKeyCommand, GetPublicKeyCommand, SignCommand } from '@aws-sdk/client-kms'
import { keccak256 } from 'ethereumjs-util'
import { createAlchemyWeb3 } from '@alch/alchemy-web3'
import log from 'ololog'

import ethutil from 'ethereumjs-util'
import asn1 from 'asn1.js'
import { BN } from 'bn.js'
import { Transaction } from 'ethereumjs-tx'

const client = new KMSClient({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID, // credentials for your IAM user
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, // credentials for your IAM user
    region: 'us-east-1'
})

const EcdsaSigAsnParse = asn1.define('EcdsaSig', async function () {
    // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
    this.seq().obj(
        this.key('r').int(),
        this.key('s').int()
    )
})

const EcdsaPubKey = asn1.define('EcdsaPubKey', async function () {
    // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
    this.seq().obj(
        this.key('algo')
            .seq()
            .obj(this.key('a').objid(), this.key('b').objid()),
        this.key('pubKey').bitstr()
    )
})

export async function createKey() {
    const createKeyCommand = new CreateKeyCommand({
        CustomerMasterKeySpec: 'ECC_SECG_P256K1',
        KeyUsage: 'SIGN_VERIFY'
    })
    const response = await client.send(createKeyCommand)
    return response.KeyMetadata.KeyId
}

export async function sign(msgHash: any, keyId: any) {
    const client = new KMSClient({
        accessKeyId: process.env.AWS_ACCESS_KEY_ID, // credentials for your IAM user
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, // credentials for your IAM user
        region: 'us-east-1'
    })

    const params = {
        KeyId: keyId,
        Message: msgHash,
        SigningAlgorithm: 'ECDSA_SHA_256',
        MessageType: 'DIGEST'
    }
    const command = new SignCommand(params)
    const response = await client.send(command)
    return response
}

export async function getPublicKey(keyID: string) {
    const getPublicKeyCommand = new GetPublicKeyCommand({
        KeyId: keyID
    })
    const response = await client.send(getPublicKeyCommand)
    return response.PublicKey
}

export async function getEthereumAddress(publicKey: ArrayBuffer | { valueOf(): ArrayBuffer | SharedArrayBuffer } | Buffer) {
    const url = process.env.ALCHEMY_URL!
    const web3 = createAlchemyWeb3(url)

    const res = await EcdsaPubKey.decode(Buffer.from(publicKey), 'der')
    let pubKeyBuffer = Buffer.from(res.pubKey.data)
    pubKeyBuffer = pubKeyBuffer.slice(1, pubKeyBuffer.length)

    const address = keccak256(pubKeyBuffer) // keccak256 hash of publicKey
    const buf2 = Buffer.from(address, 'hex')
    const ethAddr = '0x' + buf2.slice(-20).toString('hex') // take last 20 bytes as ethereum adress
    const checksum = web3.utils.toChecksumAddress(ethAddr)
    return checksum
}

export async function findEthereumSignature(plaintext: any, keyId: any) {
    const signature = await sign(plaintext, keyId)
    if (signature.Signature === undefined) {
        throw new Error('Signature is undefined.')
    }

    const decoded = await EcdsaSigAsnParse.decode(Buffer.from(signature.Signature), 'der')
    const r = new BN(decoded.r)
    let s = new BN(decoded.s)

    const secp256k1N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16) // max value on the curve
    const secp256k1halfN = secp256k1N.div(new BN(2)) // half of the curve
    // Because of EIP-2 not all elliptic curve signatures are accepted
    // the value of s needs to be SMALLER than half of the curve
    // i.e. we need to flip s if it's greater than half of the curve
    if (s.gt(secp256k1halfN)) {
        // According to EIP2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
        // if s < half the curve we need to invert it
        // s = curve.n - s
        s = secp256k1N.sub(s)
        return { r, s }
    }
    // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
    return { r, s }
}

export async function recoverAddressFromSignature(msg: any, r: { toBuffer: () => any }, s: { toBuffer: () => any }, v: number) {
    const rBuffer = r.toBuffer()
    const sBuffer = s.toBuffer()
    const publicKey = ethutil.ecrecover(msg, v, rBuffer, sBuffer)
    const addressBuffer = ethutil.pubToAddress(publicKey)
    var recoveredEthereumAddress = ethutil.bufferToHex(addressBuffer)
    return recoveredEthereumAddress
}

export async function findRightKey(msg: any, r: any, s: any, expectedEthereumAddress: any) {
    let v = 27
    let address = await recoverAddressFromSignature(msg, r, s, v)
    if (address !== expectedEthereumAddress) {
        v = 28
        address = await recoverAddressFromSignature(msg, r, s, v)
    }
    return { address, v }
}

export async function awsKmsEthereumTransactionCreate(rawTransaction: { to: any; value: any; gas: any; gasLimit: any; gasPrice: any; data: any }, sourceAddress: any, keyId: string) {
    const url = process.env.ALCHEMY_URL!
    const web3 = createAlchemyWeb3(url)

    const publicKey = await getPublicKey(keyId)
    const ethereumAddress = await getEthereumAddress(Buffer.from(publicKey))
    if (ethereumAddress !== web3.utils.toChecksumAddress(sourceAddress)) {
        return {
            success: false,
            statusCode: 9664,
            reason: 'incorrect_keyId'
        }
    }

    const ethereumAddressHash = ethutil.keccak(Buffer.from(ethereumAddress))
    const signature = await findEthereumSignature(ethereumAddressHash, keyId)
    const recoveredAddress = await findRightKey(ethereumAddressHash, signature.r, signature.s, ethereumAddress)

    const txParams = {
        to: rawTransaction.to,
        value: rawTransaction.value,
        gas: rawTransaction.gas,
        gasPrice: rawTransaction.gasPrice,
        gasLimit: rawTransaction.gasLimit,
        nonce: await web3.eth.getTransactionCount(ethereumAddress),
        data: rawTransaction.data,
        r: await signature.r.toBuffer(),
        s: await signature.s.toBuffer(),
        v: recoveredAddress.v
    }

    const transaction = new Transaction(txParams)
    const txHash = transaction.hash(false)
    const correctSignature = await findEthereumSignature(txHash, keyId)

    transaction.r = await correctSignature.r.toBuffer()
    transaction.s = await correctSignature.s.toBuffer()
    transaction.v = 27

    const senderAddress = '0x' + transaction.getSenderAddress().toString('hex')
    const senderCheckSum = web3.utils.toChecksumAddress(senderAddress)

    if (senderCheckSum === ethereumAddress) {
        return transaction
    } else {
        transaction.v = 28
        const senderAddress2 = '0x' + transaction.getSenderAddress().toString('hex')
        const senderCheckSum2 = web3.utils.toChecksumAddress(senderAddress2)
        if (senderCheckSum2 === ethereumAddress) {
            return transaction
        } else {
            await awsKmsEthereumTransactionCreate(rawTransaction, sourceAddress, keyId)
        }
    }
}

export async function sendTransaction(transaction: any) {
    console.log('sendTransaction()')
    console.log('transaction: ')
    console.log(transaction)

    if (process.env.NODE_ENVIRONMENT === 'development') {
        log.cyan('Send Transaction ---- START')
    }
    const url = process.env.ALCHEMY_ENDPOINT + process.env.ALCHEMY_KEY
    const web3 = createAlchemyWeb3(url)

    try {
        if (transaction === undefined) {
            return {
                success: false,
                statusCode: 400,
                response: 'transaction is undefined'
            }
        }
        const serializedTransaction = '0x' + (await transaction).serialize().toString('hex')
        const transactionHash = await web3.eth.sendSignedTransaction(serializedTransaction, function (error: any, hash: any) {
            if (!error) {
                if (process.env.NODE_ENVIRONMENT === 'development') { log.green('Transaction sent!', hash) }
                const interval = setInterval(async function () {
                    if (process.env.NODE_ENVIRONMENT === 'development') { console.log('Attempting to get transaction receipt...') }
                    await web3.eth.getTransactionReceipt(hash, function (err: any, rec: any) {
                        if (rec) {
                            log.green('Receipt received!')
                            clearInterval(interval)
                        }
                        if (err) { console.log(err) }
                    })
                }, 2500)
            } else {
                if (process.env.NODE_ENVIRONMENT === 'development') { console.log('Something went wrong while submitting your transaction:', error) }
            }
        })
        if (process.env.NODE_ENVIRONMENT === 'development') { log.cyan('Send Transaction ---- Complete') }
        return {
            success: true,
            statusCode: 200,
            response: {
                transactionHash: transactionHash.transactionHash,
                rawData: transactionHash
            }
        }
    } catch (error) {
        console.log(error)
        return {
            success: false,
            statusCode: 400,
            response: transaction
        }
    }
}