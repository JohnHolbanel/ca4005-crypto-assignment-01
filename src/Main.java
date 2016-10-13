import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

public class Main {

    public static void main(String[] args) {

        // prime modulus
        BigInteger p = new BigInteger("b59dd795 68817b4b 9f678982 2d22594f 376e6a9a bc024184 6de426e5 dd8f6edd ef00b465 f38f509b 2b183510 64704fe7 5f012fa3 46c5e2c4 42d7c99e ac79b2bc 8a202c98 327b9681 6cb80426 98ed3734 643c4c05 164e739c b72fba24 f6156b6f 47a7300e f778c378 ea301e11 41a6b25d 48f19242 68c62ee8 dd313474 5cdf7323", 16);

        // generator
        BigInteger g = new BigInteger("44ec9d52 c8f9189e 49cd7c70 253c2eb3 154dd4f0 8467a64a 0267c9de fe4119f2 e373388c fa350a4e 66e432d6 38ccdc58 eb703e31 d4c84e50 398f9f91 677e8864 1a2d2f61 57e2f4ec 538088dc f5940b05 3c622e53 bab0b4e8 4b1465f5 738f5496 64bd7430 961d3e5a 2e7bceb6 2418db74 7386a58f f267a993 9833beef b7a6fd68", 16);

        // Geoff's public key
        BigInteger A = new BigInteger("5af3e806 e0fa466d c75de601 86760516 792b70fd cd72a5b6 238e6f6b 76ece1f1 b38ba4e2 10f61a2b 84ef1b5d c4151e79 9485b217 1fcf318f 86d42616 b8fd8111 d59552e4 b5f228ee 838d535b 4b987f1e af3e5de3 ea0c403a 6c38002b 49eade15 171cb861 b3677324 60e3a984 2b532761 c16218c4 fea51be8 ea024838 5f6bac0d", 16);

        // my private key
        BigInteger b = new BigInteger(1023, new Random());

        // my public key
        // TODO implement modPow function
        BigInteger B = g.modPow(b, p);

        // shared key
        // TODO
        BigInteger s = A.modPow(b, p);

        // generate AES key
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(s.toByteArray());
        byte[] digest = md.digest();
        BigInteger k = new BigInteger(digest);
    }
}
