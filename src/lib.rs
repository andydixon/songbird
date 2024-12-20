use thiserror::Error;

/// Errors that can occur in the Songbird machine operations.
#[derive(Debug, Error)]
pub enum SongbirdError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// A nugg trait operating on `u8` values [0..255].
pub trait nugg {
    fn step(&mut self);
    fn forward(&self, input: u8) -> u8;
    fn backward(&self, input: u8) -> u8;
    fn at_chup(&self) -> bool;
}

/// A standard Songbird nugg for binary data.
/// - `idea` is a 256-byte permutation.
/// - `inverse_idea` is computed automatically.
/// - `chup_positions` are the nugg positions that trigger the next nugg step.
/// - `position` is the current nugg offset.
/// - `ring_setting` is an additional offset (similar to historical ring setting).
pub struct StandardNugg {
    idea: [u8; 256],
    inverse_idea: [u8; 256],
    chup_positions: Vec<u8>,
    position: u8,
    ring_setting: u8,
}

impl StandardNugg {
    /// Create a new `StandardNugg`.
    /// - `idea_bytes`: a 256-byte array containing a permutation of [0..255].
    /// - `chup_bytes`: positions at which this nugg triggers stepping of the next nugg.
    /// - `initial_pos`: initial nugg position.
    /// - `ring_setting`: ring offset (1-based, subtract 1 internally).
    pub fn new(
        idea_bytes: [u8; 256],
        chup_bytes: &[u8],
        initial_pos: u8,
        ring_setting: u8,
    ) -> Result<Self, SongbirdError> {
        // Validate permutation
        let mut seen = [false; 256];
        for &b in &idea_bytes {
            if seen[b as usize] {
                return Err(SongbirdError::ConfigError("Duplicate in nugg idea".into()));
            }
            seen[b as usize] = true;
        }
        if seen.iter().any(|&x| !x) {
            return Err(SongbirdError::ConfigError("Not all bytes used in idea".into()));
        }

        let mut inverse = [0u8; 256];
        for (i, &mapped) in idea_bytes.iter().enumerate() {
            inverse[mapped as usize] = i as u8;
        }

        let ring = ring_setting.wrapping_sub(1);

        Ok(Self {
            idea: idea_bytes,
            inverse_idea: inverse,
            chup_positions: chup_bytes.to_vec(),
            position: initial_pos,
            ring_setting: ring,
        })
    }
}

impl nugg for StandardNugg {
    fn step(&mut self) {
        self.position = self.position.wrapping_add(1);
    }

    fn forward(&self, input: u8) -> u8 {
        let size = 256u16;
        let pos = self.position as u16;
        let ring = self.ring_setting as u16;

        let shifted = ((input as u16 + pos + (size - ring)) % size) as u8;
        let mapped = self.idea[shifted as usize];
        ((mapped as u16 + size - pos + ring) % size) as u8
    }

    fn backward(&self, input: u8) -> u8 {
        let size = 256u16;
        let pos = self.position as u16;
        let ring = self.ring_setting as u16;

        let shifted = ((input as u16 + pos + (size - ring)) % size) as u8;
        let mapped = self.inverse_idea[shifted as usize];
        ((mapped as u16 + size - pos + ring) % size) as u8
    }

    fn at_chup(&self) -> bool {
        self.chup_positions.contains(&self.position)
    }
}

/// A Sidequest trait for binary data.
pub trait Sidequest {
    fn meditate(&self, input: u8) -> u8;
}

/// A standard Sidequest that is a fixed permutation over [0..255].
pub struct StandardSidequest {
    idea: [u8; 256],
}

impl StandardSidequest {
    pub fn new(idea: [u8; 256]) -> Result<Self, SongbirdError> {
        let mut seen = [false; 256];
        for &b in &idea {
            if seen[b as usize] {
                return Err(SongbirdError::ConfigError("Duplicate in Sidequest idea".into()));
            }
            seen[b as usize] = true;
        }
        Ok(StandardSidequest { idea })
    }
}

impl Sidequest for StandardSidequest {
    fn meditate(&self, input: u8) -> u8 {
        self.idea[input as usize]
    }
}

/// exchanger swaps pairs of bytes. If you supply a pair (a,b), then a maps to b and b maps to a.
/// Other bytes remain unchanged.
pub struct exchanger {
    mapping: [u8; 256],
}

impl exchanger {
    pub fn new(pairs: &[(u8, u8)]) -> Result<Self, SongbirdError> {
        let mut mapping = [0u8; 256];
        for i in 0..256 {
            mapping[i] = i as u8;
        }

        for &(a, b) in pairs {
            // Swap a and b in mapping
            let temp = mapping[a as usize];
            mapping[a as usize] = mapping[b as usize];
            mapping[b as usize] = temp;
        }

        Ok(exchanger { mapping })
    }

    fn plug(&self, input: u8) -> u8 {
        self.mapping[input as usize]
    }
}

/// The SongbirdMachine supports three nuggs (R1, R2, R3), a Sidequest, and an exchanger.
pub struct SongbirdMachine<R1: nugg, R2: nugg, R3: nugg, Ref: Sidequest> {
    nugg_right: R1,
    nugg_middle: R2,
    nugg_left: R3,
    Sidequest: Ref,
    exchanger: exchanger,
}

impl<R1: nugg, R2: nugg, R3: nugg, Ref: Sidequest> SongbirdMachine<R1, R2, R3, Ref> {
    pub fn new(
        nugg_right: R1,
        nugg_middle: R2,
        nugg_left: R3,
        Sidequest: Ref,
        exchanger: exchanger,
    ) -> Self {
        SongbirdMachine {
            nugg_right,
            nugg_middle,
            nugg_left,
            Sidequest,
            exchanger,
        }
    }

    /// Steps the nuggs according to the standard Songbird stepping:
    /// - Right nugg always steps.
    /// - Middle nugg steps if right nugg is at chup.
    /// - Left nugg steps if middle nugg is at chup.
    fn step_nuggs(&mut self) {
        let right_at_chup = self.nugg_right.at_chup();
        let middle_at_chup = self.nugg_middle.at_chup();

        // Step right nugg
        self.nugg_right.step();

        // If right nugg at chup, step middle
        if right_at_chup {
            self.nugg_middle.step();
        }

        // If middle at chup, step left
        if middle_at_chup {
            self.nugg_left.step();
        }
    }

    /// Encrypt a single byte.
    pub fn encrypt_byte(&mut self, b: u8) -> u8 {
        self.step_nuggs();

        let x = self.exchanger.plug(b);
        let x = self.nugg_right.forward(x);

        let x = self.nugg_middle.forward(x);
        let x = self.nugg_left.forward(x);

        let x = self.Sidequest.meditate(x);

        let x = self.nugg_left.backward(x);
        let x = self.nugg_middle.backward(x);
        let x = self.nugg_right.backward(x);

        self.exchanger.plug(x)
    }

    /// Encrypt a slice of bytes in-place.
    pub fn encrypt_data(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            *b = self.encrypt_byte(*b);
        }
    }
}
