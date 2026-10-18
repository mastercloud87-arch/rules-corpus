// RULE: java/insecure-bean-validation  CWE: CWE-094  LANE: taint
package corpus.java_insecure_bean_validation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintValidatorContext;
public class Case {
    // POSITIVE: a remote value becomes the EL-evaluated constraint message template
    void vulnerable(HttpServletRequest request, ConstraintValidatorContext ctx) {
        String m = request.getParameter("m");
        ctx.buildConstraintViolationWithTemplate(m).addConstraintViolation(); // EXPECT-FLAG
    }
    // NEGATIVE: a constant template -> not user-controlled
    void safe(ConstraintValidatorContext ctx) {
        ctx.buildConstraintViolationWithTemplate("{field.invalid}").addConstraintViolation(); // EXPECT-NOFLAG
    }
}
