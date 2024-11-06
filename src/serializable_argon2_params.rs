// src/serializable_argon2_params.rs

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableArgon2Params {
    pub m_cost: u32,        // Memory cost
    pub t_cost: u32,        // Time cost (iterations)
    pub p_cost: u32,        // Parallelism (threads)
    pub output_length: Option<usize>, // Output length in bytes
}

impl SerializableArgon2Params {
    // Convert to Argon2Params
    pub fn to_argon2_params(&self) -> argon2::Params {
        argon2::Params::new(
            self.m_cost,
            self.t_cost,
            self.p_cost,
            self.output_length,
        ).unwrap()
    }

    // Create from Argon2Params
    pub fn from_argon2_params(params: &argon2::Params) -> Self {
        SerializableArgon2Params {
            m_cost: params.m_cost(),
            t_cost: params.t_cost(),
            p_cost: params.p_cost(),
            output_length: params.output_len(),
        }
    }
}
