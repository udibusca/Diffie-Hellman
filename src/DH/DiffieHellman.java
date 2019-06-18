package DH;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DiffieHellman {
	private DiffieHellman() {
	}

	public static void main(String argv[]) throws Exception {

		/**
		 * Alice cria seu próprio par de chaves DH com tamanho de chave de 2048 bits
		 */
		System.out.println("ALICE: Gerar keypair DH ...");
		KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
		aliceKpairGen.initialize(2048);
		KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

		// Alice cria e inicializa seu objeto DH KeyAgreement
		System.out.println("ALICE: Initialization ...");
		KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
		aliceKeyAgree.init(aliceKpair.getPrivate());

		// Alice codifica sua chave pública e a envia para Bob.
		byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

		/**
		* Vamos virar para o Bob. Bob recebeu a chave pública de Alice em codificado
		* formato. Ele instancia uma chave pública DH do material de chave codificado.
		*/
		KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

		PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

	   /**
		* Bob recebe os parâmetros DH associados à chave pública de Alice. Ele deve usar
		* os mesmos parâmetros quando ele gera seu próprio par de chaves.
	    */
		DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey) alicePubKey).getParams();

		// Bob cria seu próprio par de chaves DH
		System.out.println("BOB: Generate DH keypair ...");
		KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
		bobKpairGen.initialize(dhParamFromAlicePubKey);
		KeyPair bobKpair = bobKpairGen.generateKeyPair();

		// Bob cria e inicializa seu objeto DH KeyAgreement
		System.out.println("BOB: Initialization ...");
		KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
		bobKeyAgree.init(bobKpair.getPrivate());

		// Bob codifica sua chave pública e a envia para Alice.
		byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

		/**
		* Alice usa a chave pública de Bob para a primeira (e única) fase de sua versão de
		* o protocolo DH. Antes que ela possa fazer isso, ela tem que instanciar uma chave pública DH
		* do material-chave codificado de Bob.
		*/
		KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
		x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
		PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
		System.out.println("ALICE: Execute PHASE1 ...");
		aliceKeyAgree.doPhase(bobPubKey, true);

		/**
		* Bob usa a chave pública de Alice para a primeira (e única) fase de sua versão de
		* o protocolo DH.
		*/
		System.out.println("BOB: Execute PHASE1 ...");
		bobKeyAgree.doPhase(alicePubKey, true);

		/**
		* Nesta fase, Alice e Bob completaram o acordo de chave DH
		* protocolo. Ambos geram o (mesmo) segredo compartilhado.
		*/
		byte[] aliceSharedSecret = aliceKeyAgree.generateSecret(); // provide output buffer of required size
		int aliceLen = aliceSharedSecret.length;
		byte[] bobSharedSecret = new byte[aliceLen];
		int bobLen;
		bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 0);
		System.out.println("Alice secret: " + toHexString(aliceSharedSecret));
		System.out.println("Bob secret: " + toHexString(bobSharedSecret));
		if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
			throw new Exception("Shared secrets differ");
		System.out.println("Shared secrets are the same");

		/**
		* Agora vamos criar um objeto SecretKey usando o segredo compartilhado e usá-lo para
		* criptografia. 
		* Primeiro, nós geramos SecretKeys para o algoritmo "AES" (baseado em os dados secretos compartilhados brutos) 
		* e depois usamos AES no modo CBC, que requer um parâmetro de vetor de inicialização (IV). 
		* Note que você tem que usar o mesmo IV para criptografia e descriptografia: 
		* se você usar um IV diferente para descriptografar
		* do que você usou para criptografia, a descriptografia falhará.
		*
		* Se você não especificar um IV ao inicializar o objeto Cipher para
		* criptografia, a implementação subjacente irá gerar um aleatório, que
		* você tem que recuperar usando o método javax.crypto.Cipher.getParameters (),
		* que retorna uma instância de java.security.AlgorithmParameters. Você precisa
		* transferir o conteúdo desse objeto (por exemplo, em formato codificado, obtido via
		* o método AlgorithmParameters.getEncoded ()) para a parte que fará o
		* descriptografia. Ao inicializar a Cifra para descriptografia, o (reinstanciado)
		* O objeto AlgorithmParameters deve ser explicitamente passado para o Cipher.init ()
		* método.
		*/
		System.out.println("Use o segredo compartilhado como objeto SecretKey ...");
		SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
		SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");

		/**
		 * Bob criptografa usando AES no modo CBC
		 */
		Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);
		byte[] cleartext = "This is just an example".getBytes();
		byte[] ciphertext = bobCipher.doFinal(cleartext);

		// Recupere o parâmetro que foi usado e transfira-o para Alice em formato codificado
		byte[] encodedParams = bobCipher.getParameters().getEncoded();

		/**
		 * Alice descriptografa usando AES no modo CBC
		 */

		// Instanciar objeto AlgorithmParameters da codificação de parâmetro obtida de Bob
		AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
		aesParams.init(encodedParams);
		Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		aliceCipher.init(Cipher.DECRYPT_MODE, aliceAesKey, aesParams);
		byte[] recovered = aliceCipher.doFinal(ciphertext);
		if (!java.util.Arrays.equals(cleartext, recovered))
			throw new Exception("AES no modo CBC recuperado texto é "+" diferente de texto não criptografado");
		System.out.println("AES no modo CBC recuperado texto é o mesmo que texto claro");
	}

	/**
	 * Converte um byte em um dígito hexadecimal e grava no buffer fornecido
	 */
	private static void byte2hex(byte b, StringBuffer buf) {
		char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		int high = ((b & 0xf0) >> 4);
		int low = (b & 0x0f);
		buf.append(hexChars[high]);
		buf.append(hexChars[low]);
	}

	/**
	 * Converte uma matriz de bytes em cadeia hexadecimal
	 */
	private static String toHexString(byte[] block) {
		StringBuffer buf = new StringBuffer();
		int len = block.length;
		for (int i = 0; i < len; i++) {
			byte2hex(block[i], buf);
			if (i < len - 1) {
				buf.append(":");
			}
		}
		return buf.toString();
	}
}