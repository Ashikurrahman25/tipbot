import dotenv from 'dotenv';
dotenv.config();

import express, { raw } from 'express';
const app = express();
import cors from 'cors';
import * as nearAPI from 'near-api-js';
import { KeyPair, utils } from 'near-api-js';
const { keyStores } = nearAPI;
const { Contract } = nearAPI;
const myKeyStore = new keyStores.InMemoryKeyStore();
import * as crypto from 'crypto';


const passphrase = process.env.PASS_PHRASE; // Replace with your secure passphrase
const salt = process.env.SALT; // Replace with a secure, consistent salt
const keyLength = 32; // AES-256 requires a 32-byte key
const iterations = 100000; // Number of iterations for PBKDF2
const digest = 'sha256'; //
const private_key = process.env.PRIVATE_KEY;

// {"publicKey":"ed25519:49c621YSa97t7Y8LePjKeKVPLD41RnZ2oKCFZS4StQo2","secretKey":"ed25519:JuhY65DQPQUHdVwJMQhXUayVxRtXx4NtcM296aeCAUkRTKAWxwKS2XfBdZGZHXN8T9K3fak55fvkG6bu63uQ3WY"}
app.use(express.json());
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({ origin: ['https://spearonnear.github.io/SpearHit', 'https://ashikurrahman25.github.io','https://spearonnear.github.io', '*'] }));

const { connect } = nearAPI;

const testConfig = {
  keyStore: myKeyStore, // first create a key store
  networkId: 'testnet',
  nodeUrl: 'https://rpc.testnet.near.org',
  walletUrl: 'https://testnet.mynearwallet.com/',
  helperUrl: 'https://helper.testnet.near.org',
  explorerUrl: 'https://testnet.nearblocks.io',
};

const mainConfig = {
  keyStore: myKeyStore, // first create a key store
  networkId: 'mainnet',
  nodeUrl: 'https://rpc.mainnet.near.org',
  walletUrl: 'https://wallet.mainnet.near.org',
  helperUrl: 'https://helper.mainnet.near.org',
  explorerUrl: 'https://nearblocks.io',
};

//{"account_id":"textroyale.near","public_key":"ed25519:6GBJeiHaW2F4YHFbDptMunmbpswPTTHTGsTNiPxgmQEH",
//"private_key":"ed25519:kodWpHkpVBoTQ7YK8fp8gxuemB69pHGhQujwhZsE9E3hKwtDtEcygwofCZbb2yEusEZnS85ry5XGwqcQHSXZC77"}

let contract: nearAPI.Contract;
let account: nearAPI.Account;

const setup = async () => {

  console.log("setup");
  const PRIVATE_KEY = decodePrivateKey(private_key!);     //"ed25519:AURW79BGK1j4bu95hqnHt5Uh9hwbA5fY2EjKUGMs9qTyjsGAmtt9AdjxwxHDctsW2NiGAMdvmv7ytzEVycBc3dt"; // Directly use the private key
  const keyPair = KeyPair.fromString(PRIVATE_KEY);
  await myKeyStore.setKey('mainnet', 'dragontip.near', keyPair);
  
  const near = await connect(
    mainConfig
  );


  account = await near.account("dragontip.near");
  const methodOptions = {
    viewMethods: ['ft_balance_of'],
    changeMethods: [`ft_transfer`,'send_ft_to_user'],
    useLocalViewExecution: true 
  };

  contract = new Contract(account,"dragontip.near",
  methodOptions
);
console.log("Setup Done");
};


 setup();


 app.post('/send', async (req, res) => {
  try {
    console.log(req.body);
    const { receiver_id, amount, memo, tkn } = req.body;

    if (!receiver_id || !amount || !tkn) {
      return res.status(400).json({ error: 'Missing "receiver_id", "amount", or "tkn" in the request body.' });
    }


    let functionCallResult;
    let gasFeeNEAR = 0;
    let transactionFeeNEAR = 0;

    if (tkn.toLowerCase() === 'near') {
      // Handle NEAR transfer
      const amountConverted = BigInt(parseFloat(amount) * Math.pow(10, 24));
      console.log(`Converted Amount (in yoctoNEAR): ${amountConverted}`);

      functionCallResult = await account.sendMoney(receiver_id, amountConverted);

      const gasUsed = BigInt(functionCallResult.transaction_outcome.outcome.gas_burnt);
      const gasFeeYoctoNEAR = parseFloat(gasUsed.toString()) * 1e-12;

      let totalTokensBurnt = BigInt(functionCallResult.transaction_outcome.outcome.tokens_burnt);
      functionCallResult.receipts_outcome.forEach(outcome => {
        totalTokensBurnt += BigInt(outcome.outcome.tokens_burnt);
      });

      gasFeeNEAR = gasFeeYoctoNEAR;
      transactionFeeNEAR = parseFloat(totalTokensBurnt.toString()) / Math.pow(10, 24);

    } else {
      // Handle custom token transfer using ft_transfer
      const amountConverted = amount; // Assuming the token uses 8 decimals
      console.log(`Converted Amount (for token transfer): ${amountConverted}`);

      functionCallResult = await account.functionCall({
        contractId: "blackdragon.tkn.near", // Token contract ID
        methodName: 'ft_transfer',
        args: {
          receiver_id,
          amount: amountConverted,
          memo,
        },
        attachedDeposit: BigInt(1) // Typically a small attached deposit is required
      });

      const gasUsed = BigInt(functionCallResult.transaction_outcome.outcome.gas_burnt);
      const gasFeeYoctoNEAR = parseFloat(gasUsed.toString()) * 1e-12;

      let totalTokensBurnt = BigInt(functionCallResult.transaction_outcome.outcome.tokens_burnt);
      functionCallResult.receipts_outcome.forEach(outcome => {
        totalTokensBurnt += BigInt(outcome.outcome.tokens_burnt);
      });

      gasFeeNEAR = gasFeeYoctoNEAR;
      transactionFeeNEAR = parseFloat(totalTokensBurnt.toString()) / Math.pow(10, 24);
    }

    let status = 'success';
    let exception = '';

    function isFailureStatus(status: any): status is { Failure: any } {
      return status && typeof status === 'object' && 'Failure' in status;
    }

    if (functionCallResult.receipts_outcome) {
      functionCallResult.receipts_outcome.forEach(outcome => {
        const outcomeStatus = outcome.outcome.status;

        if (isFailureStatus(outcomeStatus)) {
          status = 'error';
          const executionError = outcomeStatus.Failure && outcomeStatus.Failure.error_message;
          exception = executionError || JSON.stringify(outcomeStatus.Failure);
          console.error('Detailed error info:', outcomeStatus.Failure);
        }
      });
    }

    let result: any;
    if (status === 'success') {
      result = {
        success: true,
        message: `Successfully sent ${tkn === 'near' ? 'NEAR' : tkn} tokens!`,
        txnLink: `${functionCallResult.transaction_outcome.id}`,
        gasUsed: functionCallResult.transaction_outcome.outcome.gas_burnt.toString(),
        gasFee: gasFeeNEAR.toFixed(8), // Corrected calculation
        transactionFee: transactionFeeNEAR.toFixed(8)
      };
    } else {
      result = {
        success: false,
        message: exception,
        txnLink: null,
        gasUsed: functionCallResult.transaction_outcome.outcome.gas_burnt.toString(),
        gasFee: gasFeeNEAR.toFixed(8), // Corrected calculation
        transactionFee: transactionFeeNEAR.toFixed(8)
      };
    }

    res.json(result);

  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});




function deriveKey(): Buffer {
  return crypto.pbkdf2Sync(passphrase!, salt!, iterations, keyLength, digest);
}


function decodePrivateKey(encryptedData: string): string {
  try {
      const [ivHex, encrypted, authTagHex] = encryptedData.split(':');
      if (!ivHex || !encrypted || !authTagHex) {
          throw new Error('Invalid format: Missing IV, encrypted data, or auth tag');
      }

      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      const key = deriveKey(); // Derive the decryption key from the passphrase and salt
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

      decipher.setAuthTag(authTag); // Set the authentication tag

      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
  } catch (error:any) {
      console.error('Error during decryption:', error.message);
      throw new Error('Failed to decode the key. Please ensure the format is correct and the passphrase and salt are consistent.');
  }
}



const port = process.env.PORT || 9000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
