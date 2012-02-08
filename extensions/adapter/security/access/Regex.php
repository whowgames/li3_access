<?php

namespace li3_access\extensions\adapter\security\access;

use lithium\core\Libraries;
use lithium\util\Set;

class Regex extends \lithium\core\Object {

	/**
	 * The `Simple` adapter will just check for user data.
	 * It doesn't care about anything else.
	 *
	 * @param mixed $user The user data array that holds all necessary information about
	 *        the user requesting access. Or `false` (because `Auth::check()` can return `false`).
	 * @param object $request The Lithium `Request` object.
	 * @param array $options An array of additional options.
	 * @return Array An empty array if access is allowed and an array with reasons for denial
	 *         if denied.
	 */
	public function check($user, $request, array $options = array()) {
		// $defaults = array(
		// 	'scope' => $this->_config['scope'],
		// 	'rules' => $this->_config['rules'],
		// 	'default' => false,
		// );
		// $options += $defaults;
		// $user = $user ?: $this->_config['user']();

		$fields = $this->_config['fields'];
		$rules = $this->_config['rules'];
		$defaults = $this->_config['defaults'];

		// $user = $user ?: $this->_config['user']();

		// user is anonymous
		if(!$user) {
			$user = array($fields['group'] => $defaults['group']);
		}

		$current_group = $user[$fields['group']];
		$current_rules = array_merge($rules['all'], $rules[$current_group]);

		// TODO: check, if params['controller|action'] exist, at all

		$allowed = $this->requestAllowed(
			$request->params['controller'],
			$request->params['action'],
			$current_rules,
			$defaults['rule']
		);

		if($allowed) {
			return true;
		}

		return array(
			'message' => $this->_config['message'],
			'redirect' => $this->_config['redirect'],
		);
	}

	/**
	 * Checks, if the current request is allowed, based on given object and property
	 *
	 * This is a rule-parser that takes into account all given rules, implodes them,
	 * if necessary and iterates over all of them, where rules, occuring later on, are
	 * overwriting previous once. That way, you can use rules like DENY ALL first, and
	 * allow some other afterwards.
	 *
	 * A rule can be a string or an array with rules with the following structure:
	 *
	 * *:*,!*:admin_*,*:admin_index
	 *
	 * Each rule is comma-separated and _needs_ a colon as seperator between object
	 * and property. A preceding ! negates the rule, denying access to that property.
	 *
	 * @see http://debuggable.com/posts/33-lines:480f4dd6-639c-44f4-a62a-49a8cbdd56cb
	 * @param string $object 
	 * @param string $property 
	 * @param string $rules 
	 * @param string $default 
	 * @return bool true on allow, false otherwise
	 */
	function requestAllowed($object, $property, $rules, $default = false)
	{
		if(is_array($rules)) {
			$rules = implode(',', $rules);
		}

		// The default value to return if no rule matching $object/$property can be found
		$allowed = $default;
	
		// find all rules
		preg_match_all('/([^:,]+):([^,:]+)/is', $rules, $matches, PREG_SET_ORDER);
		foreach ($matches as $match) {
			list($rawMatch, $allowedObject, $allowedProperty) = $match;
		
			$allowedObject = str_replace('*', '.*', $allowedObject);
			$allowedProperty = str_replace('*', '.*', $allowedProperty);
		
			if (substr($allowedObject, 0, 1) == '!') {
				$allowedObject = substr($allowedObject, 1);
				$negativeCondition = true;
			} else {
				$negativeCondition = false;
			}
		
			if (preg_match('/^'.$allowedObject.'$/i', $object) &&
				preg_match('/^'.$allowedProperty.'$/i', $property))
			{
				$allowed = ($negativeCondition)
					? false
					: true;
			}
		}		 
		return $allowed;
	}


}

?>
