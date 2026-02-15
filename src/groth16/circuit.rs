use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_relations::r1cs::Variable;
use ark_relations::lc;

/// Demo circuit: x^3 + x + 5 = y
/// Private input: x
/// Public input: y
#[derive(Clone)]
pub struct CubeCircuit<F: PrimeField> {
    pub x: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for CubeCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Private witness: x
        let x = cs.new_witness_variable(|| {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // x2 = x * x
        let x_val = self.x;
        let x2_val = x_val.map(|x| x * x);
        let x2 = cs.new_witness_variable(|| {
            x2_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Enforce x2 = x * x
        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + x2)?;

        // x3 = x2 * x
        let x3_val = x2_val.and_then(|x2| x_val.map(|x| x2 * x));
        let x3 = cs.new_witness_variable(|| {
            x3_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Enforce x3 = x2 * x
        cs.enforce_constraint(lc!() + x2, lc!() + x, lc!() + x3)?;

        // y = x3 + x + 5
        let y_val = x3_val.and_then(|x3| x_val.map(|x| x3 + x + F::from(5u64)));
        let y = cs.new_input_variable(|| {
            y_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Enforce y = x3 + x + 5
        // x3 + x + 5 - y = 0, as a * b = c: (x3 + x + 5 - y) * 1 = 0
        cs.enforce_constraint(
            lc!() + x3 + x + (F::from(5u64), Variable::One),
            lc!() + Variable::One,
            lc!() + y,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use core::ops::Deref;

    #[test]
    fn test_cube_circuit_satisfied() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let x = Fr::from(3u64);
        let circuit = CubeCircuit { x: Some(x) };
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());

        // y should be 3^3 + 3 + 5 = 35
        let cs_inner = cs.borrow().unwrap();
        let instance = &cs_inner.deref().instance_assignment;
        // instance[0] = 1 (the "one" variable), instance[1] = y
        assert_eq!(instance[1], Fr::from(35u64));
    }

    #[test]
    fn test_cube_circuit_different_input() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let x = Fr::from(5u64);
        let circuit = CubeCircuit { x: Some(x) };
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        // 5^3 + 5 + 5 = 135
        let cs_inner = cs.borrow().unwrap();
        let instance = &cs_inner.deref().instance_assignment;
        assert_eq!(instance[1], Fr::from(135u64));
    }
}
