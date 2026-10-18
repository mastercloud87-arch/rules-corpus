// RULE: cwe502-server-dangerous-object-deserialization  CWE: CWE-502  LANE: pattern
package corpus.cwe502_server_dangerous_object_deserialization;
import java.rmi.Remote;
import java.rmi.RemoteException;
public class Case {
    // POSITIVE: a method on an RMI Remote type takes a non-primitive, non-String parameter
    interface Svc extends Remote {
        void run(Object task) throws RemoteException; // EXPECT-FLAG
    }
    // NEGATIVE: only exempt parameter types (String + primitives)
    interface SafeSvc extends Remote {
        String query(int id, String name, long ts) throws RemoteException; // EXPECT-NOFLAG
    }
}
