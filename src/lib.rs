//! DMARC aggregate report parser (RFC 9990).
//!
//! Parse DMARC aggregate reports as defined in
//! [RFC 9990](https://www.rfc-editor.org/info/rfc9990).

#![warn(clippy::pedantic)]
#![warn(
    ambiguous_negative_literals,
    closure_returning_async_block,
    explicit_outlives_requirements,
    if_let_rescope,
    let_underscore_drop,
    meta_variable_misuse,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    missing_unsafe_on_extern,
    non_ascii_idents,
    redundant_imports,
    redundant_lifetimes,
    single_use_lifetimes,
    trivial_numeric_casts,
    unit_bindings,
    unnameable_types,
    unreachable_pub,
    unsafe_attr_outside_unsafe,
    unstable_features,
    unused_import_braces,
    unused_lifetimes,
    unused_macro_rules,
    unused_qualifications,
    unused_results,
    variant_size_differences,
    clippy::absolute_paths,
    clippy::alloc_instead_of_core,
    clippy::allow_attributes,
    clippy::arithmetic_side_effects,
    clippy::as_pointer_underscore,
    clippy::as_ptr_cast_mut,
    clippy::assertions_on_result_states,
    clippy::branches_sharing_code,
    clippy::cfg_not_test,
    clippy::clear_with_drain,
    clippy::clone_on_ref_ptr,
    clippy::coerce_container_to_any,
    clippy::cognitive_complexity,
    clippy::collection_is_never_read,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::default_union_representation,
    clippy::deref_by_slicing,
    clippy::derive_partial_eq_without_eq,
    clippy::doc_include_without_cfg,
    clippy::doc_link_code,
    clippy::doc_paragraphs_missing_punctuation,
    clippy::empty_drop,
    clippy::empty_enums,
    clippy::equatable_if_let,
    clippy::error_impl_error,
    clippy::exit,
    clippy::expect_used,
    clippy::fallible_impl_from,
    clippy::filetype_is_file,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast_any,
    clippy::future_not_send,
    clippy::get_unwrap,
    clippy::if_then_some_else_none,
    clippy::impl_trait_in_params,
    clippy::imprecise_flops,
    clippy::infinite_loop,
    clippy::inline_modules,
    clippy::iter_on_empty_collections,
    clippy::iter_on_single_items,
    clippy::iter_with_drain,
    clippy::large_include_file,
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::lossy_float_literal,
    clippy::map_err_ignore,
    clippy::mem_forget,
    clippy::missing_const_for_fn,
    clippy::mod_module_files,
    clippy::module_name_repetitions,
    clippy::mutex_atomic,
    clippy::mutex_integer,
    clippy::needless_collect,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_type_cast,
    clippy::negative_feature_names,
    clippy::non_send_fields_in_send_ty,
    clippy::non_zero_suggestions,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::pointer_format,
    clippy::rc_buffer,
    clippy::rc_mutex,
    clippy::read_zero_byte_vec,
    clippy::redundant_clone,
    clippy::redundant_feature_names,
    clippy::redundant_test_prefix,
    clippy::redundant_type_annotations,
    clippy::renamed_function_params,
    clippy::return_and_then,
    clippy::same_name_method,
    clippy::search_is_some,
    clippy::set_contains_or_insert,
    clippy::significant_drop_in_scrutinee,
    clippy::significant_drop_tightening,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::str_to_string,
    clippy::string_add,
    clippy::suboptimal_flops,
    clippy::suspicious_operation_groupings,
    clippy::suspicious_xor_used_as_pow,
    clippy::tests_outside_test_module,
    clippy::todo,
    clippy::trait_duplication_in_bounds,
    clippy::transmute_undefined_repr,
    clippy::trivial_regex,
    clippy::try_err,
    clippy::tuple_array_conversions,
    clippy::type_repetition_in_bounds,
    clippy::undocumented_unsafe_blocks,
    clippy::uninhabited_references,
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc,
    clippy::unnecessary_self_imports,
    clippy::unnecessary_struct_initialization,
    clippy::unneeded_field_pattern,
    clippy::unused_peekable,
    clippy::unused_result_ok,
    clippy::unused_rounding,
    clippy::unused_trait_names,
    clippy::unwrap_used,
    clippy::use_debug,
    clippy::use_self,
    clippy::useless_let_if_seq,
    clippy::verbose_file_reads,
    clippy::volatile_composites,
    clippy::while_float,
    clippy::wildcard_dependencies
)]

pub mod borrowed;
mod common;
pub mod owned;

#[cfg(test)]
mod tests;

use quick_xml::de;
use std::io::BufRead;
use core::str::FromStr;

/// Parse a DMARC aggregate report from an XML string.
///
/// This function is zero-copy, allocating only some vectors,
/// and borrows as much from the input as possible.
/// If you would prefer an owned version, please see
/// [`from_str_owned`].
///
/// # Errors
///
/// Returns [`de::DeError`] if the XML is invalid or does not comform
/// to the DMARC aggregate report as set in RFC 9990.
pub fn from_str(s: &str) -> Result<borrowed::Report<'_>, de::DeError> {
    de::from_str(s)
}

impl<'a> TryFrom<&'a str> for borrowed::Report<'a> {
    type Error = de::DeError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        from_str(value)
    }
}

/// Parse a DMARC aggregate report from an XML string.
///
/// This function returns an owned report and performs copies from
/// the input string.
/// If you would prefer a zero-copy version, please see
/// [`from_str`].
///
/// # Errors
///
/// Returns [`de::DeError`] if the XML is invalid or does not comform
/// to the DMARC aggregate report as set in RFC 9990.
pub fn from_str_owned(s: &str) -> Result<owned::Report, de::DeError> {
    de::from_str(s)
}

impl FromStr for owned::Report {
    type Err = de::DeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        from_str_owned(s)
    }
}

impl TryFrom<&str> for owned::Report {
    type Error = de::DeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        from_str_owned(value)
    }
}

/// Parse a DMARC aggregate report from an XML reader.
///
/// # Errors
///
/// Returns [`de::DeError`] if the XML is invalid or does not comform
/// to the DMARC aggregate report as set in RFC 9990.
pub fn from_reader<T: BufRead>(reader: T) -> Result<owned::Report, de::DeError> {
    de::from_reader(reader)
}
