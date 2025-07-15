'use client';

import { useEffect, useState } from "react";

function base64urlToBigInt(base64url: string): bigint {
  const padding = "=".repeat((4 - base64url.length % 4) % 4);
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/") + padding;
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return BigInt('0x' + [...bytes].map(x => x.toString(16).padStart(2, '0')).join(''));
}

export default function Home() {
  const [publicKeyJwk, setPublicKeyJwk] = useState<any>(null);
  const [privateKeyJwk, setPrivateKeyJwk] = useState<any>(null);
  const [privateKey, setPrivateKey] = useState<CryptoKey | null>(null);
  const [publicKey, setPublicKey] = useState<CryptoKey | null>(null);
  const [plaintext, setPlaintext] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [decrypted, setDecrypted] = useState("");

  useEffect(() => {
    async function generateKeys() {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );
      setPublicKey(keyPair.publicKey);
      setPrivateKey(keyPair.privateKey);
      const pubjwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const privjwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);
      setPublicKeyJwk(pubjwk);
      setPrivateKeyJwk(privjwk);
    }
    generateKeys();
  }, []);

  const handleEncrypt = async () => {
    if (!publicKey) return;
    const encoded = new TextEncoder().encode(plaintext);
    const encrypted = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      encoded
    );
    setCiphertext(Buffer.from(new Uint8Array(encrypted)).toString('base64'));
  };

  const handleDecrypt = async () => {
    if (!privateKey || !ciphertext) return;
    const data = Uint8Array.from(Buffer.from(ciphertext, 'base64'));
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      data
    );
    setDecrypted(new TextDecoder().decode(decryptedBuffer));
    };

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-4">RSA-OAEP Demo</h1>
      <section className="mb-6">
        <h2 className="text-xl">Public Key</h2>
        <pre className="p-2 rounded max-h-40 overflow-auto">{publicKeyJwk ? JSON.stringify(publicKeyJwk, null, 2) : 'Generating...'}</pre>
      </section>
      <section className="mb-6">
        <h2 className="text-xl">Private Key</h2>
        <pre className="p-2 rounded max-h-40 overflow-auto">{privateKeyJwk ? JSON.stringify(privateKeyJwk, null, 2) : 'Generating...'}</pre>
      </section>
      {privateKeyJwk?.p && privateKeyJwk?.q && (
        <section className="mb-6">
          <h2 className="text-xl">Numbers</h2>
          <div className="text-sm overflow-auto max-h-40 p-2 border rounded font-mono">
            <p><strong>p:</strong> {base64urlToBigInt(privateKeyJwk.p).toString()}</p>
            <p><strong>q:</strong> {base64urlToBigInt(privateKeyJwk.q).toString()}</p>
            <p><strong>public n:</strong> {base64urlToBigInt(publicKeyJwk.n).toString()}</p>
            <p><strong>private n:</strong> {base64urlToBigInt(privateKeyJwk.n).toString()}</p>
            <p><strong>d:</strong> {base64urlToBigInt(privateKeyJwk.d).toString()}</p>
            <p><strong>e:</strong> {base64urlToBigInt(privateKeyJwk.e).toString()}</p>
          </div>
        </section>
      )}
      <section className="mb-6">
        <textarea
          className="w-full p-2 border rounded"
          rows={3}
          placeholder="Enter plaintext"
          value={plaintext}
          onChange={(e) => setPlaintext(e.target.value)}
        />
        <button
          className="mt-2 px-4 py-2 bg-blue-500 text-white rounded"
          onClick={handleEncrypt}
        >
          Encrypt
        </button>
      </section>
      {ciphertext && (
        <section className="mb-6">
          <h2 className="text-xl">Ciphertext (Base64)</h2>
          <textarea className="w-full p-2 border rounded" rows={4} readOnly value={ciphertext} />
          <button
            className="mt-2 px-4 py-2 bg-green-500 text-white rounded"
            onClick={handleDecrypt}
          >
            Decrypt
          </button>
        </section>
      )}
      {decrypted && (
        <section>
          <h2 className="text-xl">Decrypted Text</h2>
          <p className="p-2 border rounded">{decrypted}</p>
        </section>
      )}
    </div>
  );
}
