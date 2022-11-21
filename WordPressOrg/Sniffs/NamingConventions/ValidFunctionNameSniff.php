<?php
/**
 * WordPress Coding Standard.
 *
 * @package WPCS\WordPressCodingStandards
 * @link    https://github.com/WordPress/WordPress-Coding-Standards
 * @license https://opensource.org/licenses/MIT MIT
 */

namespace WordPressCS\WordPressOrg\Sniffs\NamingConventions;

use WordPressCS\WordPressOrg\Sniff;
use PHPCSUtils\BackCompat\BCTokens;
use PHPCSUtils\Utils\FunctionDeclarations;
use PHPCSUtils\Utils\ObjectDeclarations;
use PHPCSUtils\Utils\Scopes;

/**
 * Enforces WordPress function name and method name format, based upon Squiz code.
 *
 * @link    https://make.wordpress.org/core/handbook/best-practices/coding-standards/php/#naming-conventions
 *
 * @package WPCS\WordPressCodingStandards
 *
 * @since   0.1.0
 * @since   0.13.0 Class name changed: this class is now namespaced.
 * @since   2.0.0  The `get_name_suggestion()` method has been moved to the
 *                 WordPress native `Sniff` base class as `get_snake_case_name_suggestion()`.
 * @since   2.2.0  Will now ignore functions and methods which are marked as @deprecated.
 * @since   3.0.0  This sniff has been refactored and no longer extends the upstream
 *                 PEAR.NamingConventions.ValidFunctionName sniff.
 */
class ValidFunctionNameSniff extends Sniff {

	/**
	 * Returns an array of tokens this test wants to listen for.
	 *
	 * @since 3.0.0
	 *
	 * @return array
	 */
	public function register() {
		return array( \T_FUNCTION );
	}

	/**
	 * Processes this test, when one of its tokens is encountered.
	 *
	 * @since 3.0.0
	 *
	 * @param int $stackPtr The position of the current token in the stack.
	 *
	 * @return int|void Integer stack pointer to skip forward or void to continue
	 *                  normal file processing.
	 */
	public function process_token( $stack_ptr ) {

		if ( Sniff::is_function_deprecated( $this->phpcsFile, $stack_ptr ) === true ) {
			/*
			 * Deprecated functions don't have to comply with the naming conventions,
			 * otherwise functions deprecated in favour of a function with a compliant
			 * name would still trigger an error.
			 */
			return;
		}

		$name = FunctionDeclarations::getName( $this->phpcsFile, $stack_ptr );
		if ( empty( $name ) === true ) {
			// Live coding or parse error.
			return;
		}

		if ( '' === ltrim( $name, '_' ) ) {
			// Ignore special functions, like __().
			return;
		}

		$oo_ptr = Scopes::validDirectScope( $this->phpcsFile, $stack_ptr, BCTokens::ooScopeTokens() );
		if ( false === $oo_ptr ) {
			$this->process_function_declaration( $stack_ptr, $name );
		} else {
			$this->process_method_declaration( $stack_ptr, $name, $oo_ptr );
		}
	}

	/**
	 * Processes a function declaration for a function in the global namespace.
	 *
	 * @since 0.1.0
	 * @since 3.0.0 Renamed from `processTokenOutsideScope()` to `process_function_declaration()`.
	 *              Method signature has been changed as well as this method no longer overloads
	 *              a method from the PEAR sniff which was previously the sniff parent.
	 *
	 * @param int    $stackPtr     The position where this token was found.
	 * @param string $functionName The name of the function.
	 *
	 * @return void
	 */
	protected function process_function_declaration( $stack_ptr, $function_name ) {

		// PHP magic functions are exempt from our rules.
		if ( FunctionDeclarations::isMagicFunctionName( $function_name ) === true ) {
			return;
		}

		// Is the function name prefixed with "__" ?
		if ( preg_match( '`^__[^_]`', $function_name ) === 1 ) {
			$error     = 'Function name "%s" is invalid; only PHP magic methods should be prefixed with a double underscore';
			$error_data = array( $function_name );
			$this->phpcsFile->addError( $error, $stack_ptr, 'FunctionDoubleUnderscore', $error_data );
		}

		if ( strtolower( $function_name ) !== $function_name ) {
			$error     = 'Function name "%s" is not in snake case format, try "%s"';
			$error_data = array(
				$function_name,
				$this->get_snake_case_name_suggestion( $function_name ),
			);
			$this->phpcsFile->addError( $error, $stack_ptr, 'FunctionNameInvalid', $error_data );
			$this->phpcsFile->fixer->replaceToken( $stack_ptr + 2, $this->get_snake_case_name_suggestion( $function_name ) );
		}
	}

	/**
	 * Processes a method declaration.
	 *
	 * @since 0.1.0
	 * @since 3.0.0 Renamed from `processTokenWithinScope()` to `process_method_declaration()`.
	 *              Method signature has been changed as well as this method no longer overloads
	 *              a method from the PEAR sniff which was previously the sniff parent.
	 *
	 * @param int    $stackPtr   The position where this token was found.
	 * @param string $methodName The name of the method.
	 * @param int    $currScope  The position of the current scope.
	 *
	 * @return void
	 */
	protected function process_method_declaration( $stack_ptr, $method_name, $curr_scope ) {

		if ( \T_ANON_CLASS === $this->tokens[ $curr_scope ]['code'] ) {
			$class_name = '[Anonymous Class]';
		} else {
			$class_name = ObjectDeclarations::getName( $this->phpcsFile, $curr_scope );
		}

		$method_name_lc = strtolower( $method_name );
		$class_name_lc  = strtolower( $class_name );

		// PHP4 constructors are allowed to break our rules.
		if ( $method_name_lc === $class_name_lc ) {
			return;
		}

		// PHP4 destructors are allowed to break our rules.
		if ( '_' . $class_name_lc === $method_name_lc ) {
			return;
		}

		// PHP magic methods are exempt from our rules.
		if ( FunctionDeclarations::isMagicMethodName( $method_name ) === true ) {
			return;
		}

		$extended   = ObjectDeclarations::findExtendedClassName( $this->phpcsFile, $curr_scope );
		$interfaces = ObjectDeclarations::findImplementedInterfaceNames( $this->phpcsFile, $curr_scope );

		// If this is a child class or interface implementation, it may have to use camelCase or double underscores.
		if ( ! empty( $extended ) || ! empty( $interfaces ) ) {
			return;
		}

		// Is the method name prefixed with "__" ?
		if ( preg_match( '`^__[^_]`', $method_name ) === 1 ) {
			$error     = 'Method name "%s" is invalid; only PHP magic methods should be prefixed with a double underscore';
			$error_data = array( $class_name . '::' . $method_name );
			$this->phpcsFile->addError( $error, $stack_ptr, 'MethodDoubleUnderscore', $error_data );
		}

		// Check for all lowercase.
		if ( $method_name_lc !== $method_name ) {
			$error     = 'Method name "%s" in class %s is not in snake case format, try "%s"';
			$error_data = array(
				$method_name,
				$class_name,
				$this->get_snake_case_name_suggestion( $method_name ),
			);
			$this->phpcsFile->addError( $error, $stack_ptr, 'MethodNameInvalid', $error_data );
			$this->phpcsFile->fixer->replaceToken( $stack_ptr + 2, $this->get_snake_case_name_suggestion( $method_name ) );
		}
	}

}
