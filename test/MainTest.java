import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

/**
 * Created by jacob on 14/10/2016.
 */
public class MainTest {
    @Test
    public void rtlModExp() throws Exception {
        BigInteger test1 = new BigInteger("598");
        BigInteger test2 = new BigInteger("675");
        BigInteger test3 = new BigInteger("809");

        BigInteger test = test1.modPow(test2, test3);
        assertEquals(Main.rtlModExp(test1, test2, test3), test);
    }

    @Test
    public void ltrModExp() throws Exception {
        BigInteger test1 = new BigInteger("598");
        BigInteger test2 = new BigInteger("675");
        BigInteger test3 = new BigInteger("809");

        BigInteger test = test1.modPow(test2, test3);
        assertEquals(Main.ltrModExp(test1, test2, test3), test);
    }

}