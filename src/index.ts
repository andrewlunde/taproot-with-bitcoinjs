import {
    initEccLib,
    networks,
    Signer,
    payments,
    crypto,
    Psbt
} from "bitcoinjs-lib";
import { broadcast, waitUntilUTXO } from "./blockstream_utils";
import { ECPairFactory, ECPairAPI, TinySecp256k1Interface,ECPairInterface } from 'ecpair';
import { generateMnemonic,mnemonicToSeedSync,validateMnemonic } from 'bip39';
import BIP32Factory, { BIP32Interface } from 'bip32';
import * as ecc from 'tiny-secp256k1';

import { input, confirm, number, select } from '@inquirer/prompts';

const tinysecp: TinySecp256k1Interface = require('tiny-secp256k1');
initEccLib(tinysecp as any);
const ECPair: ECPairAPI = ECPairFactory(tinysecp);
const network = networks.testnet;
const bip32 = BIP32Factory(ecc);

async function start() {

    const mnemonic = 'mass erosion auction border truly until paper stairs blur increase object acquire';
    const seed = mnemonicToSeedSync(mnemonic)
    const root: BIP32Interface = bip32.fromSeed(seed,network);

    var index = 0;
    var utxopath = "m/86'/1'/0'" + "/0/"+index.toString();

    console.log("utxopath:  " + utxopath);
                        
    var child1: BIP32Interface = root.derivePath(utxopath);

    var privkey = child1.privateKey;

    var keypair = null; 
    if (privkey !== undefined) {
        console.log("Creating keypair from mnemonic.");
        keypair = ECPair.fromPrivateKey(privkey, { network: network });
    } else {
        console.log("Creating random keypair.");
        keypair = ECPair.makeRandom({ network });
    }
    
    

    await start_p2pktr(keypair);
}

async function start_p2pktr(keypair: Signer) {
    console.log(`Running "Pay to Pubkey with taproot example"`);
    // Tweak the original keypair
    const tweakedSigner = tweakSigner(keypair, { network });
    // Generate an address from the tweaked public key
    const p2pktr = payments.p2tr({
        pubkey: toXOnly(tweakedSigner.publicKey),
        network
    });
    const p2pktr_addr = p2pktr.address ?? "";

    const yes_continue = await confirm({ message: 'Continue?' });

    if (!yes_continue) {
        process.exit(1);
    } else {
        console.log(`Waiting till UTXO is detected at this Address: ${p2pktr_addr}`);

        const utxos = await waitUntilUTXO(p2pktr_addr);

        if (false) {
            console.log(`Using UTXO ${utxos[0].txid}:${utxos[0].vout}`);

            const psbt = new Psbt({ network });
            psbt.addInput({
                hash: utxos[0].txid,
                index: utxos[0].vout,
                witnessUtxo: { value: utxos[0].value, script: p2pktr.output! },
                tapInternalKey: toXOnly(keypair.publicKey)
            });

            psbt.addOutput({
                address: "mohjSavDdQYHRYXcS3uS6ttaHP8amyvX78", // faucet address
                value: utxos[0].value - 150
            });

            psbt.signInput(0, tweakedSigner);
            psbt.finalizeAllInputs();

            const tx = psbt.extractTransaction();
            console.log(`Broadcasting Transaction Hex: ${tx.toHex()}`);
            const txid = await broadcast(tx.toHex());
            console.log(`Success! Txid is ${txid}`);
        } else {
            console.log(`Found UTXO ${utxos[0].txid}:${utxos[0].vout}`);
        }
    }
}

start().then(() => process.exit());

function tweakSigner(signer: Signer, opts: any = {}): Signer {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    let privateKey: Uint8Array | undefined = signer.privateKey!;
    if (!privateKey) {
        throw new Error('Private key is required for tweaking signer!');
    }
    if (signer.publicKey[0] === 3) {
        privateKey = tinysecp.privateNegate(privateKey);
    }

    const tweakedPrivateKey = tinysecp.privateAdd(
        privateKey,
        tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash),
    );
    if (!tweakedPrivateKey) {
        throw new Error('Invalid tweaked private key!');
    }

    return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
        network: opts.network,
    });
}

function tapTweakHash(pubKey: Buffer, h: Buffer | undefined): Buffer {
    return crypto.taggedHash(
        'TapTweak',
        Buffer.concat(h ? [pubKey, h] : [pubKey]),
    );
}

function toXOnly(pubkey: Buffer): Buffer {
    return pubkey.subarray(1, 33)
}
