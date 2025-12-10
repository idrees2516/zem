// Twist Protocol Module
// Read-write memory checking with increments and locality optimization

pub mod protocol;
pub mod increment;
pub mod less_than;
pub mod val_evaluation;
pub mod read_check;
pub mod write_check;
pub mod locality;
pub mod virtual_memory;

pub use protocol::{TwistProtocol, TwistConfig};
pub use increment::{IncrementComputation, IncrementStore};
pub use less_than::{LessThanPredicate, LessThanMLE};
pub use val_evaluation::ValEvaluationSumCheck;
pub use read_check::TwistReadCheck;
pub use write_check::TwistWriteCheck;
pub use locality::LocalityAwareTwistProver;
pub use virtual_memory::VirtualMemoryValues;
