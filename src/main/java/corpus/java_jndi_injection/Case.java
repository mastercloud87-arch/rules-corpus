// RULE: java/jndi-injection  CWE: CWE-074  LANE: taint
package corpus.java_jndi_injection;
import jakarta.servlet.http.HttpServletRequest;
import javax.naming.InitialContext;
import javax.naming.NamingException;
public class Case {
    // POSITIVE: a remote value becomes the JNDI lookup name
    Object vulnerable(HttpServletRequest request) throws NamingException {
        String url = request.getParameter("url");
        return new InitialContext().lookup(url); // EXPECT-FLAG
    }
    // NEGATIVE: a constant JNDI name -> not user-controlled
    Object safe() throws NamingException {
        return new InitialContext().lookup("java:comp/env/jdbc/AppDB"); // EXPECT-NOFLAG
    }
}
