<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace League\OAuth2\Client\Provider;

use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

/**
 * MindMeister
 *
 * @author Robert Pitt <rob@biggerplate.com>
 */
class MindMeister extends AbstractProvider
{
	/**
	 * Use the Authorization Trait
	 */
	use \League\OAuth2\Client\Tool\BearerAuthorizationTrait;

	/**
	 * MindMeister root domain
	 */
	public $domain = 'https://www.mindmeister.com/';

	/**
	 * API Domain 
	 */
	public $apiDomain = 'https://www.mindmeister.com/api/v2/';

	public function getBaseAuthorizationUrl()
	{
		return $this->domain . 'oauth2/authorize';
	}

	/**
	 * Get access token url to retrieve token
	 *
	 * @param array $params
	 * @return string
	 */
	public function getBaseAccessTokenUrl(array $params)
	{
		return $this->domain . 'oauth2/token';
	}

	/**
	 * Get provider url to fetch user details.
	 * 
	 * NOTE:
	 * By default twitter does not allow to retrieve email address.
	 * To get access to user email application need to be whitelisted by twitter.
	 *
	 * @param AccessToken $token
	 * @return string
	 */
	public function getResourceOwnerDetailsUrl(AccessToken $token)
	{
		return $this->apiDomain . 'users/me';
	}

	/**
	 * Get the default scopes used by this provider.
	 *
	 * This should not be a complete list of all scopes, but the minimum
	 * required for the provider user interface!
	 *
	 * @return array
	 */
	protected function getDefaultScopes()
	{
		return [];
	}

	protected function checkResponse(ResponseInterface $response, $data)
	{
		if ($response->getStatusCode() >= 400)
		{
			$message = '';
			if (!empty($data['errors']) && is_array($data['errors']))
			{
				$error = array_shift($data['errors']);
				if (!empty($error['code']))
				{
					$message .= $error['code'];
				}
				if (!empty($error['code']) && !empty($error['message']))
				{
					$message .= ': ';
				}
				if (!empty($error['message']))
				{
					$message .= $error['message'];
				}
			}


			throw new IdentityProviderException( $message ? : $response->getReasonPhrase(), $response->getStatusCode(), $response);
		}
	}

	protected function createResourceOwner(array $response, AccessToken $token)
	{
		return (new MindMeisterResourceOwner($response));
	}

}
