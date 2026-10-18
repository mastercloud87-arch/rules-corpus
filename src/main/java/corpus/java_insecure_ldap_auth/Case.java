// RULE: java/insecure-ldap-auth  CWE: CWE-522  LANE: pattern
package corpus.java_insecure_ldap_auth;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
public class Case {
    // POSITIVE: simple-bind credentials sent over a plaintext ldap:// URL
    DirContext vulnerable() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.PROVIDER_URL, "ldap://ldap.example.com:389");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_CREDENTIALS, "s3cret");
        return new InitialDirContext(env); // EXPECT-FLAG
    }
    // NEGATIVE: same credentials over an encrypted ldaps:// channel
    DirContext safe() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.PROVIDER_URL, "ldaps://ldap.example.com:636");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_CREDENTIALS, "s3cret");
        return new InitialDirContext(env); // EXPECT-NOFLAG
    }
}
