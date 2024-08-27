"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const express_1 = __importDefault(require("express"));
const app = (0, express_1.default)();
const cors_1 = __importDefault(require("cors"));
const nearAPI = __importStar(require("near-api-js"));
const near_api_js_1 = require("near-api-js");
const { keyStores } = nearAPI;
const { Contract } = nearAPI;
const myKeyStore = new keyStores.InMemoryKeyStore();
// {"publicKey":"ed25519:49c621YSa97t7Y8LePjKeKVPLD41RnZ2oKCFZS4StQo2","secretKey":"ed25519:JuhY65DQPQUHdVwJMQhXUayVxRtXx4NtcM296aeCAUkRTKAWxwKS2XfBdZGZHXN8T9K3fak55fvkG6bu63uQ3WY"}
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true, limit: '10mb' }));
app.use((0, cors_1.default)({ origin: ['https://spearonnear.github.io/SpearHit', 'https://ashikurrahman25.github.io', 'https://spearonnear.github.io', '*'] }));
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
let contract;
let account;
const setup = () => __awaiter(void 0, void 0, void 0, function* () {
    console.log("setup");
    const PRIVATE_KEY = "ed25519:AURW79BGK1j4bu95hqnHt5Uh9hwbA5fY2EjKUGMs9qTyjsGAmtt9AdjxwxHDctsW2NiGAMdvmv7ytzEVycBc3dt"; // Directly use the private key
    const keyPair = near_api_js_1.KeyPair.fromString(PRIVATE_KEY);
    yield myKeyStore.setKey('testnet', 'dragontip.testnet', keyPair);
    const near = yield connect(testConfig);
    account = yield near.account("dragontip.testnet");
    const methodOptions = {
        viewMethods: ['ft_balance_of'],
        changeMethods: [`ft_transfer`, 'send_ft_to_user'],
        useLocalViewExecution: true
    };
    contract = new Contract(account, "dragontip.testnet", methodOptions);
    console.log("Setup Done");
});
setup();
app.post('/send', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
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
            // Send NEAR tokens
            functionCallResult = yield account.sendMoney(receiver_id, amountConverted);
            // Extract gas used and calculate the gas fee
            const gasUsed = BigInt(functionCallResult.transaction_outcome.outcome.gas_burnt);
            const gasFeeYoctoNEAR = parseFloat(gasUsed.toString()) * 1e-12; // Convert gas used to NEAR
            // Extract transaction fee (total tokens burnt)
            let totalTokensBurnt = BigInt(functionCallResult.transaction_outcome.outcome.tokens_burnt);
            // Add up tokens burnt from the receipts outcomes
            functionCallResult.receipts_outcome.forEach(outcome => {
                totalTokensBurnt += BigInt(outcome.outcome.tokens_burnt);
            });
            // Convert the total fee from yoctoNEAR to NEAR
            gasFeeNEAR = gasFeeYoctoNEAR;
            transactionFeeNEAR = parseFloat(totalTokensBurnt.toString()) / Math.pow(10, 24);
        }
        else {
            // Handle custom token transfer using ft_transfer
            const amountConverted = (parseFloat(amount) * Math.pow(10, 8)).toString(); // Assuming the token uses 8 decimals
            console.log(`Converted Amount (for token transfer): ${amountConverted}`);
            functionCallResult = yield account.functionCall({
                contractId: tkn, // Token contract ID
                methodName: 'ft_transfer',
                args: {
                    receiver_id,
                    amount: amountConverted,
                    memo,
                },
                attachedDeposit: BigInt(1) // Typically a small attached deposit is required
            });
            // Similar process for calculating gas and transaction fees
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
        function isFailureStatus(status) {
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
        let result;
        if (status === 'success') {
            result = {
                success: true,
                message: `Successfully sent ${tkn === 'near' ? 'NEAR' : tkn} tokens!`,
                txnLink: `https://nearblocks.io/txns/${functionCallResult.transaction_outcome.id}`,
                gasUsed: functionCallResult.transaction_outcome.outcome.gas_burnt.toString(),
                gasFee: gasFeeNEAR.toFixed(8), // Corrected calculation
                transactionFee: transactionFeeNEAR.toFixed(8)
            };
        }
        else {
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
    }
    catch (error) {
        res.status(500).json({ error: error.message });
    }
}));
const port = process.env.PORT || 9000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
