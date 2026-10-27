/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::classifier::{Optimizer, gradient, model::FhClassifier};

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default)]
pub struct Sgd {
    parameters: Vec<f32>,
    bias: f32,
    alpha: f64,
    l1_ratio: f64,
    l2_ratio: f64,
    t: f64,
    w_scale: f32,
    optimal_init: f64,
    eta: f32,
    u: f32,
    q: Vec<f32>,
}

impl Sgd {
    pub fn new(n_features: usize, alpha: f64, l1_ratio: f64, l2_ratio: f64) -> Self {
        let typw = (1.0 / alpha.sqrt()).sqrt();
        let initial_eta0 = typw / 1.0_f64.max(gradient(1.0, -typw as f32) as f64);
        let optimal_init = 1.0 / (initial_eta0 * alpha);

        Sgd {
            parameters: vec![0.0; n_features],
            bias: 0.0,
            alpha,
            l1_ratio,
            l2_ratio,
            t: 0.0,
            w_scale: 1.0,
            optimal_init,
            eta: initial_eta0 as f32,
            u: 0.0,
            q: vec![0.0; n_features],
        }
    }

    pub fn with_initial_parameters(self, value: f32) -> Self {
        Sgd {
            parameters: vec![value; self.parameters.len()],
            ..self
        }
    }

    fn maybe_rescale(&mut self) {
        if !(1e-6..=1e6).contains(&self.w_scale) {
            for w in &mut self.parameters {
                *w *= self.w_scale;
            }
            self.w_scale = 1.0;
        }
    }

    #[inline(always)]
    fn apply_l1_penalty(&mut self) {
        if self.l1_ratio > 0.0 {
            for (z, q) in self.parameters.iter_mut().zip(self.q.iter_mut()) {
                let z_orig = *z;
                let scaled_z = *z * self.w_scale;
                if scaled_z > 0.0 {
                    *z = (*z - (self.u + *q) / self.w_scale).max(0.0);
                } else if scaled_z < 0.0 {
                    *z = (*z + (self.u - *q) / self.w_scale).min(0.0);
                }
                *q += self.w_scale * (z_orig - *z);
            }
        }
    }
}

impl Optimizer for Sgd {
    fn step(&mut self) {
        self.t += 1.0;
        self.eta = (1.0 / ((self.alpha) * (self.optimal_init + self.t - 1.0))) as f32;
        self.w_scale *= 1.0 - ((1.0 - self.l1_ratio) as f32 * self.eta * self.l2_ratio as f32);
        self.u += self.eta * self.l1_ratio as f32 * self.alpha as f32;
    }

    fn update_param(&mut self, i: usize, g: f32) {
        self.parameters[i] += (-self.eta * g) / self.w_scale;
    }

    fn update_bias(&mut self, g: f32) {
        self.bias += -self.eta * g;
        self.maybe_rescale();
        self.apply_l1_penalty();
    }

    #[inline(always)]
    fn get_param(&self, idx: usize) -> f32 {
        self.parameters[idx] * self.w_scale
    }

    #[inline(always)]
    fn get_bias(&self) -> f32 {
        self.bias
    }

    #[inline(always)]
    fn get_param_mut(&mut self, idx: usize) -> &mut f32 {
        &mut self.parameters[idx]
    }

    fn build_classifier(&self) -> FhClassifier {
        FhClassifier {
            parameters: self.parameters.iter().map(|w| w * self.w_scale).collect(),
            bias: self.bias,
        }
    }

    fn num_parameters(&self) -> usize {
        self.parameters.len()
    }
}

