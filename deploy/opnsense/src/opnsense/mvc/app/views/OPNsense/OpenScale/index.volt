{#
 # OpenScale settings page (#885): read and write the settings, then
 # reconfigure (render /etc/rc.conf.d/openscale and restart the service).
 #}

<script>
    $(document).ready(function () {
        mapDataToFormUI({'frm_general': "/api/openscale/settings/get"}).done(function () {
            $('.selectpicker').selectpicker('refresh');
            updateServiceControlUI('openscale');
        });

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/openscale/settings/set", 'frm_general', function () {
                    dfObj.resolve();
                }, true, function () {
                    dfObj.reject();
                });
                return dfObj;
            },
            onAction: function () {
                updateServiceControlUI('openscale');
            }
        });
    });
</script>

<div class="content-box __mb">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
</div>
<section class="page-content-main">
    <div class="content-box">
        <div class="col-md-12">
            <br/>
            <button class="btn btn-primary" id="reconfigureAct"
                    data-endpoint="/api/openscale/service/reconfigure"
                    data-label="{{ lang._('Apply') }}"
                    data-error-title="{{ lang._('OpenScale could not be started') }}"
                    type="button"></button>
            <br/><br/>
        </div>
    </div>
</section>
