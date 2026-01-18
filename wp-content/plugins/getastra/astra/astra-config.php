<?php




if (!defined('CZ_DEBUG')) {

    define("CZ_DEBUG", FALSE);
}


define("CZ_SETUP", TRUE);

define("CZ_TURBO", TRUE);


define("CZ_UPDATE", FALSE);

define("CZ_ASTRA_CLIENT_VERSION", "0.0.5");

define("CZ_PLATFORM", "wordpress");



define("CZ_ASTRA_ACTIVE", TRUE);

define("CZ_CZAR_IP", "https:");



define("CZ_API_URL", "https://dash.getastra.com/api/post");

define("CZ_BLOCK_PAGE_URL", "https://dash.getastra.com/blocked");



define("CZ_SECRET_KEY", "6c315e650fd7c313878e97b1f55493c16fffdc8b");

define("CZ_CLIENT_KEY", "98479270ffc52845dbae6d1b344ec43188e3b169");

define("CZ_ACCESS_KEY", "0C1FF565BD3CE4EE8A051622C5973D54");

define("CZ_SITE_KEY", "Xx95s7T0");

/* define("CZ_DB_PATH", ""); */
/* define("CZ_IP_HEADER", "HTTP_CF_CONNECTING_IP"); */

define("CZ_SCAN_ARRAYS", "GET,POST");

define("CZ_FILE_UPLOAD_SCAN",'file_upload_scan');

define("CZ_BASE_URL", dirname(dirname(__FILE__)));

define("CZ_FIREWALL_URL", dirname(__FILE__) . '/');

define("CZ_CONFIG_PATH", CZ_FIREWALL_URL . basename(__FILE__));



define("CZ_DATABASE_NAME", "ImrR5dFZt4UbgNaX81xB");

define("CZ_JSON_EXCLUDE_ALL", FALSE);
define("CZ_ALLOW_FOREIGN_CHARS", FALSE);

define("CZ_ASTRA_MODE", "block");

define("CZ_CONFIG_LVL", "medium");

if (!function_exists('get_cz_lvl')) {

    function get_cz_lvl() {
        return array
            (
            "low" => array
                (
                "ip_blocking" => Array
                    (
                    "duration" => 50,
                    "count" => 5,
                ),
                "bot_blocking" => Array
                    (
                    "duration" => 60,
                    "count" => 1,
                ),
                "token_bucket" => Array
                    (
                    "minute" => 60,
                    "minute_limit" => 150,
                ),
            ),
            "medium" => array
                (
                "ip_blocking" => Array
                    (
                    "duration" => 200,
                    "count" => 5,
                ),
                "bot_blocking" => Array
                    (
                    "duration" => 60,
                    "count" => 1,
                ),
                "token_bucket" => Array
                    (
                    "minute" => 60,
                    "minute_limit" => 100,
                ),
            ),
            "high" => array
                (
                "ip_blocking" => Array
                    (
                    "duration" => 300,
                    "count" => 1,
                ),
                "bot_blocking" => Array
                    (
                    "duration" => 60,
                    "count" => 1,
                ),
                "token_bucket" => Array
                    (
                    "minute" => 60,
                    "minute_limit" => 50,
                ),
            )
        );
    }

}

$cz_lvl = get_cz_lvl();

$debug_log = "";

function show_astra_debug_log(){
    global $debug_log;

    if (CZ_DEBUG) {
        echo $debug_log;
    }
}

function echo_debug($str) {
    global $debug_log;
    $debug_log .= "<p>" . json_encode($str) . "</p>\r\n";
}


?>
