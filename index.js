//Importing libraries
const bip39 = require('bip39');
const hdKey = require('hdkey');
const createHash = require('create-hash');
const base58Check = require('bs58check');

// Generating a 12 words string Mnemonic using 128 bits entropy

const mnemonic = bip39.generateMnemonic();

// Converting the Mnemonic to seed buffer phrase without a phraprase
//by running 2048 rounds of HMAC-SHA512 
//The below method is generating the seed synchronously
const seed =  bip39.mnemonicToSeedSync(mnemonic)

//Converting the seed Hex to buffer
let seedHex = seed.toString('hex');

//Generating the root of the HD Tree, whereby the MasterPrivate and MasterPublic Keys can be generated
const root = hdKey.fromMasterSeed(Buffer.from(seedHex,'hex'));

//Generate extended public key
console.log("Extended Public key: ",root.publicExtendedKey)
//Generate the Master Private Key
const masterPrivateKey = root.privateKey.toString('hex')

//You can use the .derive method to generate child key by providing a path.

// m purpose/coin-type/account/chain/index
// 44 means BIP 44 purpose for HD wallets ,
// 0 means bitcoin,
// 0 means first account,
//0 means its recieving address if its change it will be one
//0 menas index
const address1 = root.derive("m/44'/0'/0'/0/0")

// Get the public key
const publicKey = address1.publicKey

//Hashing the public key with sha256 and ripemd 160
const hashedPublicKey = createHash('sha256').update(publicKey).digest();
const doubleHashedPublicKey = createHash('rmd160').update(hashedPublicKey).digest();

//doubleHashedPublicKey is the address

// adding base58check

//create a new buffer
var add = Buffer.allocUnsafe(21);

// add checksum version 0x00 for mainnet, 0x6f for testnet
add.writeUInt8(0x00, 0)
doubleHashedPublicKey.copy(add,1);

const address = base58Check.encode(doubleHashedPublicKey);

console.log('Base58Check: ' + address);







