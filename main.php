<?php

require __DIR__ . '/vendor/autoload.php';

use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;

// ------------------------------
// step 1 - create the payload
// ------------------------------

$payload = json_encode([
  'email' => 'test@gmail.com',
  'firstName' => 'Hello',
  'lastName' => 'World',
  'companyName' => 'ABC Inc.',
  'countryCode' => 'US',
  'phoneNumber' => '+1 202 555 0157',
  'taxId' => '123456789',
]);

// ---------------------------------------------------------------------------------------------------------------
// step 2 - sign the payload
// - documentation can be found at https://web-token.spomky-labs.com/the-components/signed-tokens-jws/jws-creation
// ---------------------------------------------------------------------------------------------------------------

$partnerPrivateKey = new JWK([
  "kty" => "RSA",
  "n" => "i6JkTrJYp8t9S-6njD3aq2D-FWQOSdGm0611r2YD-vrNv9oVi78KedRoWtTxmjYUtH6z5bHiVDjAHqi6erHsVJNuLqhEUsVZJd4TFiMnczSFPrywKpkgxbT82HJUooE-OSsS9OENbBDMH-4fNCwap3gyDGxVNKCPDrSz-9vuwyXExhomTFjNjIJFlZ2earrw2JFQPEo5DLkVZriMBwS-spZ30VGk2gNTMWYfpI6Kw02pd9Uy1ODyKNbWMKrsSanVRJSnl8ofQx_ofm0vF3c4kbH2rY9YaG9GrCfmmFDHg5jGlAaCEMuaRfUGsFais3zW9f2r5QrLe3vhkECQZaqp",
  "e" => "AQAB",
  "d" => "U7u58wc36sc4B8TBbHPbIVI0i5dIijPSmrU2EUxXrrWflCCvMvII0i3xtiZkC1nK6MHiFyeo1WCCtN_xk4oGcmFGfWwiLJBzeSXGxEuoaIliLdDww1q4MFbsGM_WuOxP5_BQmdArQFaCUdN1ms-n3C1Ttedw4PI3V1Y9aBbnAsjtZSTHEU_lygBXG7XgxaXZ4pnST6q1mCx8ijUXY1YnGhLV7r6Qla-nb0elzdshIQrhZvssaP5s7gh6yr5fsYHOC-UUvSQt3RMDkQIyuAZZ37GU6UA3eBaozyIUzpGpsYs0q3nIuQlp1ZOOVn3RmFlXoxLQJ-wo2_6EHgCdl_VB",
  "p" => "DS9jA1uDGZWVByDaeLM0p8SHYWzCkAx-5gAwE52F0hYIqvDAid4EFYPYwDkv3X2bgEgBidn9H_VUPNmtwXCZH1Y-YLslhJqZtvChqHPNoaen2hUYglHwWcwBzTynbZQ6MfPdnFR8NUZ1fIF5mhpcb9qSbqfA39dTMKj51wCBvXU",
  "q" => "CpcejDLxvqNiFpYS_6EpyRKs0-5bcYw9JETGLRBSkt4hD7glDHbyRrtQ8QM2OrY0nyrjhGnh3wSDlZPZfQxhFii95zXvkZuv5GrSOvm0PWmvle33Z6St0tJ2YTRLQnWUC9I54JM7g5MPDFYktGcNbGcp4X0F8NgEFIC1BfqPTeU",
  "dp" => "CAoHjemDMttAZXtDmepyRYSPovhkXN4xlV0x8xPNnz2uBUQLsUP8K34bb4CuzZajdIDy5zFRo-W6eeujhNl5k2DLYcFZ69MzvBZWCtao31LRBihsrDD3oljAFHpR_38sSH7PdV0R6o3OXp63HR3LlKupMuz3rcOlRnsQ8mWttW0",
  "dq" => "CQzibz_uNlQcNF8md018jzileCw_-4a0jbU0gzhqyNaJ_IwLJV7VZ7sWzhFHm98wk0Gs0_FEtTl_VinW-LXGlpBU0i3WwWICbDsZ1IqnDMCv7HpEL0-duQhhYGq3UmF3Fq8fBRvuBWB8wLcxgPZ8k0KKmQgmNo_01Ky1hxl8tD0",
  "qi" => "B3hv6ds736LnGI9M7Ft14Ktj42tFSJ71ANDoaRWLiNIkN5R8-6_6RvhTC6H3Le7foxEfODUGyerkmiA1_IofabKgaU5hYv_VZhRSUPb9-T9mK64T6-5RRj4T2_qjjwsXjmdtQZFIkBW7IoZqWnDbsUh88pT9f-AufEyUvrA1NQk"
]);

$jwsAlgorithmManager = new AlgorithmManager([
  new RS256(),
]);

$jwsBuilder = new JWSBuilder($jwsAlgorithmManager);

$jws = $jwsBuilder
  ->create()
  ->withPayload($payload)
  ->addSignature($partnerPrivateKey, ['alg' => 'RS256'])
  ->build();

$jwsSerializer = new Jose\Component\Signature\Serializer\CompactSerializer();
$signedToken = $jwsSerializer->serialize($jws, 0);

// ------------------------------------------------------------------------------------------------------------------
// step 3 - encrypting the signed token
// - documentation can be found at https://web-token.spomky-labs.com/the-components/encrypted-tokens-jwe/jwe-creation
// ------------------------------------------------------------------------------------------------------------------

// - SF Auth Server public key is available in JWK format at
//   - staging: https://auth-staging.shipafreightservices.com/jwks
//   - production: https://auth-staging.shipafreightservices.com/jwks
$shipaFreightAuthServerPublicKey = new JWK([
  'kty' => 'RSA',
  'e' => 'AQAB',
  'n' => 'mSW8tmE1zJwyVbi2imOeVfTnNuyyA7QxX94Iu0S2kyK9CbqlMDWoObk8ZjWh7WZP8v0o3T_ZspMF8nyuVvHFudhP9yAtaN5etvxFd3imYVt-tt2lA_vBToT-Yg5Vd5W5yOqbSTgb_sWl_2piU1PawlWX_aJbyS_MiNRkFUA_k-v1Y9BQmNVgxQJyDwVuFKDiMiy_yhdpgrA_JcLvXtIyG8OZ0aAhEo8sF_OrqfVKtGdbmrOpsz0j7YQfyZKPjw2AnyuPRk3gMPhzmPWPM4zSAMHRIJxSJnHYU-63jtFd2zFLp4-shZGDywYbeDhjpj5kw4TDcV_QRmwiZ2dvLbhT',
]);

$keyEncryptionAlgorithmManager = new AlgorithmManager([
  new RSAOAEP(),
]);

$contentEncryptionAlgorithmManager = new AlgorithmManager([
  new A128CBCHS256(),
]);

$compressionMethodManager = new CompressionMethodManager([
  new Deflate(0),
]);

$jweBuilder = new JWEBuilder(
  $keyEncryptionAlgorithmManager,
  $contentEncryptionAlgorithmManager,
  $compressionMethodManager
);

$jwe = $jweBuilder
    ->create()
    ->withPayload($signedToken)
    ->withSharedProtectedHeader([
      'alg' => 'RSA-OAEP',
      'enc' => 'A128CBC-HS256',
      'zip' => 'DEF'
    ])
    ->addRecipient($shipaFreightAuthServerPublicKey)
    ->build();

$jweSerializer = new Jose\Component\Encryption\Serializer\CompactSerializer();
$encryptedToken = $jweSerializer->serialize($jwe, 0);

echo $encryptedToken;
