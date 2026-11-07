<?php

/*
 * Reads and writes the OpenScale settings (#885). The base class checks
 * the ACL, the CSRF token and the model's validation; no value reaches a
 * shell from here.
 */

namespace OPNsense\OpenScale\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'openscale';
    protected static $internalModelClass = 'OPNsense\OpenScale\OpenScale';
}
