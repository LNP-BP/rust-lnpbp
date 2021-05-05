//! This is a planned API for v0.5.0 that will help structuring RGB validation
//! into a more formal process

/// This simple trait MUST be used by all parties implementing client-side
/// validation paradigm. The core concept of this paradigm is that a client
/// must have a complete and uniform set of data, which can be represented
/// or accessed through a single structure; and MUST be able to
/// deterministically validate this set giving an external validation function,
/// that is able to provide validator with
pub trait ClientSideValidate<Resolver>
where
    Resolver: TrustResolver,
{
    type ClientData: ClientData;
    type ValidationError: FromTrustProblem<Resolver>
        + FromInternalInconsistency<Resolver>;

    fn new() -> Self;

    fn client_side_validate(
        client_data: Self::ClientData,
        trust_resolver: Resolver,
    ) -> Result<(), Self::ValidationError> {
        let validator = Self::new();
        client_data.validate_internal_consistency()?;
        client_data.validation_iter().try_for_each(|item| {
            trust_resolver
                .resolve_trust(item, validator.get_context_for_atom(item))?;
            item.client_side_validate()
        })
    }

    fn get_context_for_item<Ctx>(
        &self,
        data_item: Self::ClientData::ValidationItem,
    ) -> Ctx;
}

pub trait ClientData {
    type ValidationItem: ClientData;
}

/// Trust resolver for a given client data type MUST work with a single type
/// of [`TrustResolver::Context`], defined by an associated type. Trust
/// resolution MUST always produce a singular success type (defined by `()`) or
/// fail with a well-defined type of [`TrustResolver::TrustProblem`].
///
/// Trust resolver may have an internal state (represented by `self` reference)
/// and it does not require to produce a deterministic result for the same
/// given data piece and context: the trust resolver may depend on previous
/// operation history and depend on type and other external parameters.
pub trait TrustResolver<T: ClientData> {
    type TrustProblem: std::error::Error;
    type Context;
    fn resolve_trust(
        &self,
        data_piece: &T,
        context: &Self::Context,
    ) -> Result<(), Self::TrustProblem>;
}
