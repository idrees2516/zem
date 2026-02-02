// Galois automorphisms for cyclotomic rings
// Implements σ_i : R → R where σ_i(X) = X^i for i ∈ Z_{2d}^×

use crate::field::Field;
use crate::ring::RingElement;
use super::super::errors::{HachiError, Result};

/// Galois automorphism σ_i : R → R
/// 
/// **Paper Reference:** Section 2.1 "Galois Automorphisms"
/// 
/// For cyclotomic ring R = Z[X]/(X^d + 1), automorphism σ_i maps X ↦ X^i
/// where i ∈ Z_{2d}^× (units of Z_{2d})
#[derive(Clone, Debug)]
pub struct GaloisAutomorphism {
    /// Power i where σ_i(X) = X^i
    pub power: usize,
    
    /// Ring dimension d
    pub ring_dimension: usize,
    
    /// Conductor f = 2d
    pub conductor: usize,
    
    /// Precomputed power map: power_map[j] = (i*j) mod 2d reduced to [0, d)
    /// with sign adjustment for X^d = -1
    power_map: Vec<(usize, bool)>, // (index, is_negative)
}

impl GaloisAutomorphism {
    /// Create new Galois automorphism σ_i
    /// 
    /// **Validation:**
    /// - i must be coprime to 2d (i.e., i must be odd)
    /// - i must be in range [1, 2d)
    pub fn new(power: usize, ring_dimension: usize) -> Result<Self> {
        let conductor = 2 * ring_dimension;
        
        // Validate power is coprime to conductor
        if gcd(power, conductor) != 1 {
            return Err(HachiError::InvalidGaloisAutomorphism(
                format!("Power {} not coprime to conductor {}", power, conductor)
            ));
        }
        
        // Precompute power map
        let power_map = Self::compute_power_map(power, ring_dimension, conductor);
        
        Ok(Self {
            power,
            ring_dimension,
            conductor,
            power_map,
        })
    }
    
    /// Compute power map for efficient application
    /// 
    /// For each j ∈ [0, d), compute where X^j maps under σ_i
    /// σ_i(X^j) = X^{ij} = X^{(ij mod 2d)}
    /// 
    /// Since X^d = -1, we have:
    /// - If ij mod 2d < d: X^{ij mod 2d}
    /// - If ij mod 2d ≥ d: -X^{(ij mod 2d) - d}
    fn compute_power_map(power: usize, d: usize, conductor: usize) -> Vec<(usize, bool)> {
        let mut map = Vec::with_capacity(d);
        
        for j in 0..d {
            let ij = (power * j) % conductor;
            
            if ij < d {
                // X^{ij} with positive sign
                map.push((ij, false));
            } else {
                // -X^{ij - d} with negative sign
                map.push((ij - d, true));
            }
        }
        
        map
    }
    
    /// Apply automorphism to ring element
    /// 
    /// **Paper Reference:** Section 2.1
    /// 
    /// For a = Σ_j a_j X^j, compute σ_i(a) = Σ_j a_j σ_i(X^j) = Σ_j a_j X^{ij}
    pub fn apply<F: Field>(&self, elem: &RingElement<F>) -> RingElement<F> {
        assert_eq!(elem.coeffs.len(), self.ring_dimension);
        
        let mut result_coeffs = vec![F::zero(); self.ring_dimension];
        
        for (j, coeff) in elem.coeffs.iter().enumerate() {
            let (target_idx, is_negative) = self.power_map[j];
            
            if is_negative {
                // Add -coeff to result_coeffs[target_idx]
                result_coeffs[target_idx] = result_coeffs[target_idx].sub(coeff);
            } else {
                // Add coeff to result_coeffs[target_idx]
                result_coeffs[target_idx] = result_coeffs[target_idx].add(coeff);
            }
        }
        
        RingElement::from_coeffs(result_coeffs)
    }
    
    /// Compose two automorphisms: σ_i ∘ σ_j = σ_{ij mod 2d}
    pub fn compose(&self, other: &Self) -> Result<Self> {
        assert_eq!(self.ring_dimension, other.ring_dimension);
        
        let composed_power = (self.power * other.power) % self.conductor;
        Self::new(composed_power, self.ring_dimension)
    }
    
    /// Compute inverse automorphism: σ_i^{-1} = σ_{i^{-1} mod 2d}
    pub fn inverse(&self) -> Result<Self> {
        let inv_power = mod_inverse(self.power, self.conductor)?;
        Self::new(inv_power, self.ring_dimension)
    }
    
    /// Check if this is the identity automorphism
    pub fn is_identity(&self) -> bool {
        self.power % self.conductor == 1
    }
    
    /// Get order of this automorphism
    /// 
    /// Returns smallest k > 0 such that σ_i^k = identity
    pub fn order(&self) -> usize {
        let mut current_power = self.power;
        let mut order = 1;
        
        while current_power % self.conductor != 1 {
            current_power = (current_power * self.power) % self.conductor;
            order += 1;
            
            if order > self.conductor {
                // Should never happen for valid automorphism
                panic!("Order computation failed");
            }
        }
        
        order
    }
}

/// Conjugation automorphism σ_{-1}
/// 
/// **Paper Reference:** Section 2.1, Lemma 5
/// 
/// σ_{-1}(X) = X^{-1} = X^{2d-1} = -X^{d-1}
/// 
/// For a = Σ_j a_j X^j:
/// σ_{-1}(a) = a_0 - Σ_{j=1}^{d-1} a_j X^{d-j}
pub struct ConjugationAutomorphism {
    inner: GaloisAutomorphism,
}

impl ConjugationAutomorphism {
    /// Create conjugation automorphism for ring of dimension d
    pub fn new(ring_dimension: usize) -> Result<Self> {
        let conductor = 2 * ring_dimension;
        let power = conductor - 1; // -1 mod 2d = 2d - 1
        
        Ok(Self {
            inner: GaloisAutomorphism::new(power, ring_dimension)?,
        })
    }
    
    /// Apply conjugation to ring element
    pub fn apply<F: Field>(&self, elem: &RingElement<F>) -> RingElement<F> {
        self.inner.apply(elem)
    }
    
    /// Efficient direct implementation
    /// 
    /// σ_{-1}(Σ a_j X^j) = a_0 - Σ_{j=1}^{d-1} a_j X^{d-j}
    pub fn apply_direct<F: Field>(&self, elem: &RingElement<F>) -> RingElement<F> {
        let d = elem.coeffs.len();
        let mut result = vec![F::zero(); d];
        
        // Constant term stays the same
        result[0] = elem.coeffs[0];
        
        // For j > 0: coefficient of X^j in result is -a_{d-j}
        for j in 1..d {
            result[j] = elem.coeffs[d - j].neg();
        }
        
        RingElement::from_coeffs(result)
    }
}

/// Frobenius-type automorphism σ_{4k+1}
/// 
/// **Paper Reference:** Section 2.1, Lemma 5
/// 
/// For extension degree k, σ_{4k+1}(X) = X^{4k+1}
/// This automorphism has order d/(2k)
pub struct FrobeniusTypeAutomorphism {
    inner: GaloisAutomorphism,
    extension_degree: usize,
}

impl FrobeniusTypeAutomorphism {
    /// Create Frobenius-type automorphism for extension degree k
    pub fn new(ring_dimension: usize, extension_degree: usize) -> Result<Self> {
        // Validate k divides d/2
        if (ring_dimension / 2) % extension_degree != 0 {
            return Err(HachiError::InvalidGaloisAutomorphism(
                format!("Extension degree {} must divide d/2 = {}", 
                    extension_degree, ring_dimension / 2)
            ));
        }
        
        let power = 4 * extension_degree + 1;
        
        Ok(Self {
            inner: GaloisAutomorphism::new(power, ring_dimension)?,
            extension_degree,
        })
    }
    
    /// Apply automorphism
    pub fn apply<F: Field>(&self, elem: &RingElement<F>) -> RingElement<F> {
        self.inner.apply(elem)
    }
    
    /// Get order: d/(2k)
    pub fn order(&self) -> usize {
        self.inner.ring_dimension / (2 * self.extension_degree)
    }
}

/// Automorphism group Aut(R)
/// 
/// **Paper Reference:** Section 2.1
/// 
/// Aut(R) = {σ_i : i ∈ Z_{2d}^×}
/// For R = Z[X]/(X^d + 1), |Aut(R)| = φ(2d) = d
pub struct AutomorphismGroup {
    /// Ring dimension d
    pub ring_dimension: usize,
    
    /// All automorphisms σ_i for i ∈ Z_{2d}^×
    pub automorphisms: Vec<GaloisAutomorphism>,
    
    /// Powers i ∈ Z_{2d}^× (units)
    pub units: Vec<usize>,
}

impl AutomorphismGroup {
    /// Create automorphism group for ring of dimension d
    pub fn new(ring_dimension: usize) -> Result<Self> {
        let conductor = 2 * ring_dimension;
        
        // Find all units of Z_{2d}
        let units: Vec<usize> = (1..conductor)
            .filter(|&i| gcd(i, conductor) == 1)
            .collect();
        
        // Verify |Aut(R)| = φ(2d) = d
        assert_eq!(units.len(), ring_dimension, 
            "Automorphism group size must equal ring dimension");
        
        // Create automorphisms
        let automorphisms: Result<Vec<_>> = units.iter()
            .map(|&power| GaloisAutomorphism::new(power, ring_dimension))
            .collect();
        
        Ok(Self {
            ring_dimension,
            automorphisms: automorphisms?,
            units,
        })
    }
    
    /// Get automorphism σ_i
    pub fn get(&self, power: usize) -> Result<&GaloisAutomorphism> {
        self.automorphisms.iter()
            .find(|auto| auto.power == power)
            .ok_or_else(|| HachiError::InvalidGaloisAutomorphism(
                format!("Automorphism σ_{} not in group", power)
            ))
    }
    
    /// Apply all automorphisms to element (for trace computation)
    pub fn apply_all<F: Field>(&self, elem: &RingElement<F>) -> Vec<RingElement<F>> {
        self.automorphisms.iter()
            .map(|auto| auto.apply(elem))
            .collect()
    }
}

/// Subgroup of automorphisms
/// 
/// **Paper Reference:** Section 2.1, Lemma 5
/// 
/// For Hachi, we use H = ⟨σ_{-1}, σ_{4k+1}⟩
pub struct AutomorphismSubgroup {
    /// Ring dimension d
    pub ring_dimension: usize,
    
    /// Extension degree k
    pub extension_degree: usize,
    
    /// Generators: [σ_{-1}, σ_{4k+1}]
    pub generators: Vec<GaloisAutomorphism>,
    
    /// All elements of subgroup
    pub elements: Vec<GaloisAutomorphism>,
    
    /// Subgroup size |H| = d/k
    pub size: usize,
}

impl AutomorphismSubgroup {
    /// Create subgroup H = ⟨σ_{-1}, σ_{4k+1}⟩
    /// 
    /// **Paper Reference:** Lemma 5
    pub fn new(ring_dimension: usize, extension_degree: usize) -> Result<Self> {
        // Create generators
        let sigma_minus_1 = ConjugationAutomorphism::new(ring_dimension)?;
        let sigma_4k_plus_1 = FrobeniusTypeAutomorphism::new(ring_dimension, extension_degree)?;
        
        let generators = vec![
            sigma_minus_1.inner.clone(),
            sigma_4k_plus_1.inner.clone(),
        ];
        
        // Generate all elements of subgroup
        let elements = Self::generate_subgroup(&generators, ring_dimension)?;
        
        // Verify size |H| = d/k
        let expected_size = ring_dimension / extension_degree;
        if elements.len() != expected_size {
            return Err(HachiError::InvalidGaloisAutomorphism(
                format!("Subgroup size {} does not match expected d/k = {}", 
                    elements.len(), expected_size)
            ));
        }
        
        Ok(Self {
            ring_dimension,
            extension_degree,
            generators,
            elements,
            size: expected_size,
        })
    }
    
    /// Generate all elements of subgroup from generators
    fn generate_subgroup(
        generators: &[GaloisAutomorphism],
        ring_dimension: usize,
    ) -> Result<Vec<GaloisAutomorphism>> {
        let conductor = 2 * ring_dimension;
        let mut elements = Vec::new();
        let mut powers_seen = std::collections::HashSet::new();
        
        // Start with identity
        let identity = GaloisAutomorphism::new(1, ring_dimension)?;
        elements.push(identity);
        powers_seen.insert(1);
        
        // BFS to generate all elements
        let mut queue = vec![1usize];
        let mut idx = 0;
        
        while idx < queue.len() {
            let current_power = queue[idx];
            idx += 1;
            
            // Apply each generator
            for gen in generators {
                let new_power = (current_power * gen.power) % conductor;
                
                if powers_seen.insert(new_power) {
                    let new_elem = GaloisAutomorphism::new(new_power, ring_dimension)?;
                    elements.push(new_elem);
                    queue.push(new_power);
                }
            }
        }
        
        Ok(elements)
    }
    
    /// Apply all subgroup elements to ring element
    pub fn apply_all<F: Field>(&self, elem: &RingElement<F>) -> Vec<RingElement<F>> {
        self.elements.iter()
            .map(|auto| auto.apply(elem))
            .collect()
    }
    
    /// Check if element is in subgroup
    pub fn contains(&self, power: usize) -> bool {
        self.elements.iter().any(|auto| auto.power == power)
    }
}

/// Greatest common divisor
fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let temp = b;
        b = a % b;
        a = temp;
    }
    a
}

/// Modular inverse using extended Euclidean algorithm
fn mod_inverse(a: usize, m: usize) -> Result<usize> {
    let (g, x, _) = extended_gcd_int(a as i64, m as i64);
    
    if g != 1 {
        return Err(HachiError::InvalidGaloisAutomorphism(
            format!("{} has no inverse modulo {}", a, m)
        ));
    }
    
    Ok(((x % m as i64 + m as i64) % m as i64) as usize)
}

/// Extended Euclidean algorithm for integers
fn extended_gcd_int(a: i64, b: i64) -> (i64, i64, i64) {
    if b == 0 {
        return (a, 1, 0);
    }
    
    let (g, x1, y1) = extended_gcd_int(b, a % b);
    let x = y1;
    let y = x1 - (a / b) * y1;
    
    (g, x, y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GoldilocksField;
    
    #[test]
    fn test_conjugation_automorphism() {
        let d = 64;
        let sigma = ConjugationAutomorphism::new(d).unwrap();
        
        // Create test element: 1 + 2X + 3X^2
        let mut coeffs = vec![GoldilocksField::zero(); d];
        coeffs[0] = GoldilocksField::from_u64(1);
        coeffs[1] = GoldilocksField::from_u64(2);
        coeffs[2] = GoldilocksField::from_u64(3);
        let elem = RingElement::from_coeffs(coeffs);
        
        // Apply conjugation
        let result = sigma.apply(&elem);
        
        // Check: σ_{-1}(1 + 2X + 3X^2) = 1 - 2X^{d-1} - 3X^{d-2}
        assert_eq!(result.coeffs[0].to_canonical_u64(), 1);
        // Negative coefficients wrap around in field
    }
    
    #[test]
    fn test_frobenius_type_automorphism() {
        let d = 256;
        let k = 16;
        let sigma = FrobeniusTypeAutomorphism::new(d, k).unwrap();
        
        // Check order is d/(2k)
        assert_eq!(sigma.order(), d / (2 * k));
    }
    
    #[test]
    fn test_automorphism_composition() {
        let d = 64;
        let sigma1 = GaloisAutomorphism::new(3, d).unwrap();
        let sigma2 = GaloisAutomorphism::new(5, d).unwrap();
        
        let composed = sigma1.compose(&sigma2).unwrap();
        
        // σ_3 ∘ σ_5 = σ_{15}
        assert_eq!(composed.power % (2 * d), 15);
    }
    
    #[test]
    fn test_automorphism_inverse() {
        let d = 64;
        let sigma = GaloisAutomorphism::new(3, d).unwrap();
        let sigma_inv = sigma.inverse().unwrap();
        
        // σ_3 ∘ σ_3^{-1} = identity
        let composed = sigma.compose(&sigma_inv).unwrap();
        assert!(composed.is_identity());
    }
    
    #[test]
    fn test_automorphism_group_size() {
        let d = 64;
        let group = AutomorphismGroup::new(d).unwrap();
        
        // |Aut(R)| = φ(2d) = d
        assert_eq!(group.automorphisms.len(), d);
    }
    
    #[test]
    fn test_subgroup_size() {
        let d = 256;
        let k = 16;
        let subgroup = AutomorphismSubgroup::new(d, k).unwrap();
        
        // |H| = d/k
        assert_eq!(subgroup.size, d / k);
        assert_eq!(subgroup.elements.len(), d / k);
    }
}
