const { mnemonicToSeed } = require("@scure/bip39");
const ecc = require("tiny-secp256k1");
const { BIP32Factory } = require("bip32");
const bip32 = BIP32Factory(ecc);
const { HMAC } = require("fast-sha256");
const secp256k1 = require("secp256k1");
const lnurl = require("@zerologin/lnurl");

const stringToUint8Array = (str) => {
  return Uint8Array.from(str, (x) => x.charCodeAt(0));
};

const seedFromWords = async (mnemonic) => {
  const seed = await mnemonicToSeed(mnemonic);
  return Buffer.from(seed);
};
async function go() {
  const lnurlObject = lnurl.decode(
    "lightning:LNURL1DP68GURN8GHJ7MRFVA58GMNFDENKCMM8D9HZUMRFWEJJ7MR0VA5KU0MTXY7NWCNYXSMKVCEKX3JRSCF4X3SKXWTXXASNGVE5XQ6RZDMXXC6KXDE3VYCRZCENXF3NQVF5XCEXZE3JXVMRGVRY8YURJVNYV43RGDRRVGN8GCT884KX7EMFDCV8DETA"
  );
  const domain = lnurlObject.domain;

  const mn =
    "praise you muffin lion enable neck grocery crumble super myself license ghost";
  const seed = await seedFromWords(mn);
  console.log(seed.toString("hex"));
  const root = bip32.fromSeed(seed);

  console.log({ root }, root);
  const hashingKey = root.derivePath(`m/138'/0`);
  const hashingPrivKey = hashingKey.privateKey;
  console.log({ hashingPrivKey });

  if (!hashingPrivKey) throw new Error("Cannot derive pub key");
  const derivationMaterial = new HMAC(hashingPrivKey)
    .update(stringToUint8Array(domain))
    .digest();
  console.log({ derivationMaterial });
  const pathSuffix = new Uint32Array(derivationMaterial.buffer.slice(0, 16));
  console.log({ pathSuffix });
  const path = `m/138'/${pathSuffix.join("/")}`;
  console.log({ path });

  const linkingKey = root.derivePath(path);
  console.log({ linkingKey });
}

go();
