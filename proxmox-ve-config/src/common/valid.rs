use std::ops::Deref;

/// A wrapper type for validatable structs.
///
/// It can only be constructed by implementing the [`Validatable`] type for a struct. Its contents
/// can be read, but not modified, guaranteeing the content of this struct to always be valid, as
/// defined by the [`Validatable::validate`] function.
///
/// If you want to edit the content, this struct has to be unwrapped via [`Valid<T>::into_inner`].
#[repr(transparent)]
#[derive(Clone, Default, Debug)]
pub struct Valid<T>(T);

impl<T> Valid<T> {
    /// returns the wrapped value owned, consumes the Valid struct
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Valid<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> AsRef<T> for Valid<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

/// Defines a struct that can be validated
///
/// This can be useful if a struct can not be validated solely by its structure, for instance if
/// the validity of a value of a field depends on another field. This trait can help with
/// abstracting that requirement away and implementing it provides the only way of constructing a
/// [`Valid<T>`].
pub trait Validatable: Sized {
    type Error;

    /// Checks whether the values in the struct are valid or not.
    fn validate(&self) -> Result<(), Self::Error>;

    /// Calls [`Validatable::validate`] to validate the struct and returns a [`Valid<T>`] if
    /// validation succeeds.
    fn into_valid(self) -> Result<Valid<Self>, Self::Error> {
        self.validate()?;
        Ok(Valid(self))
    }
}
