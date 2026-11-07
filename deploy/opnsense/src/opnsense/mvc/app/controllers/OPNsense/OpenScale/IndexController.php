<?php

/*
 * OpenScale settings page (#885): one form, saved through the settings
 * API and applied through the service API.
 */

namespace OPNsense\OpenScale;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->pick('OPNsense/OpenScale/index');
    }
}
