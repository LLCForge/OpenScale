<?php

/*
 * Starts, stops and reconfigures the OpenScale service (#885). The base
 * class renders the template (/etc/rc.conf.d/openscale) and calls the
 * fixed configd actions in actions_openscale.conf; no request parameter
 * is passed to them.
 */

namespace OPNsense\OpenScale\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\OpenScale\OpenScale';
    protected static $internalServiceTemplate = 'OPNsense/OpenScale';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'openscale';
}
