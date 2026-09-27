<?php
/*
 * FlowSight inside the pfSense web GUI.
 *
 * flowsightd binds to loopback and ships no authentication of its own; the
 * GUI has already authenticated the user (and checked the privilege
 * page-services-flowsight, /etc/inc/priv/flowsight.priv.inc), so this page
 * is the only door:
 *
 *   flowsight.php            the page, inside the pfSense chrome
 *   flowsight.php?app=1      the FlowSight application shell (in an iframe)
 *   flowsight.php?asset=…    static files of the shell
 *   flowsight.php?api=/api/… JSON API, GET and POST
 *
 * CSRF. pfSense's csrf-magic takes its token from a POST form field, which a
 * JSON request does not have, so for the app, its assets and its API this
 * page turns csrf-magic's automatic check (and its HTML rewriting) off, loads
 * it deferred, hands the app a csrf-magic token, and on every write checks
 * the token the app returns in the X-CSRFToken header with csrf-magic's own
 * validation, and an Origin (or Referer) matching this host. The page itself
 * keeps pfSense's default protection. The GUI user's name travels to the
 * daemon in X-Flowsight-User so the audit log names people.
 */

##|+PRIV
##|*IDENT=page-services-flowsight
##|*NAME=Services: FlowSight
##|*DESCR=Allow access to FlowSight (Services > FlowSight).
##|*MATCH=flowsight.php*
##|-PRIV

$fs_raw = isset($_GET["api"]) || isset($_GET["asset"]) || isset($_GET["app"]);
if ($fs_raw) {
    $nocsrf = true;
}
require_once("guiconfig.inc");
if ($fs_raw) {
    function csrf_startup()
    {
        csrf_conf('defer', true);
        csrf_conf('rewrite', false);
        csrf_conf('expires', 240 * 60);
    }
    require_once("csrf/csrf-magic.php");
}

$FLOWSIGHT_BASE = "http://127.0.0.1:8080";

/* The daemon trusts the loopback proxy only while no API token is set. Once
 * an operator sets one (to reach the API from the LAN as well), this page
 * presents it, read from the daemon's own config, so the GUI keeps working. */
function fs_api_token()
{
    static $tok = null;
    if ($tok !== null) {
        return $tok;
    }
    $tok = "";
    $cfg = @json_decode(@file_get_contents("/usr/local/etc/flowsight/flowsight.json"), true);
    /* Core keys (bind, port, api_token) live at the top level of the file. */
    if (is_array($cfg) && !empty($cfg["api_token"]) && is_string($cfg["api_token"])) {
        $tok = $cfg["api_token"];
    }
    return $tok;
}

function fs_fetch($url, $method = "GET", $body = null, $headers = [])
{
    $ch = curl_init($url);
    $hdrs = array_merge(["X-Requested-With: Flowsight"], $headers);
    if (fs_api_token() !== "") {
        $hdrs[] = "X-Flowsight-Token: " . fs_api_token();
    }
    if (!empty($_SESSION["Username"])) {
        $hdrs[] = "X-Flowsight-User: " . preg_replace('/[^A-Za-z0-9@._-]/', '', $_SESSION["Username"]);
    }
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 120,
        CURLOPT_HEADER => true,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $hdrs,
    ]);
    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hsize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $err = curl_error($ch);
    curl_close($ch);
    if ($resp === false) {
        return [null, 0, [], $err];
    }
    $rawh = substr($resp, 0, $hsize);
    $out = substr($resp, $hsize);
    $rh = [];
    foreach (explode("\r\n", $rawh) as $line) {
        if (strpos($line, ":") !== false) {
            list($k, $v) = explode(":", $line, 2);
            $rh[strtolower(trim($k))] = trim($v);
        }
    }
    return [$out, $code, $rh, $err];
}

function fs_same_origin()
{
    $host = $_SERVER["HTTP_HOST"] ?? "";
    foreach (["HTTP_ORIGIN", "HTTP_REFERER"] as $h) {
        if (!empty($_SERVER[$h])) {
            $u = parse_url($_SERVER[$h]);
            $ohost = ($u["host"] ?? "") . (isset($u["port"]) ? ":" . $u["port"] : "");
            $hostOnly = explode(":", $host)[0];
            return $ohost === $host || ($u["host"] ?? "") === $hostOnly;
        }
    }
    return false;
}

function fs_fail($code, $msg)
{
    http_response_code($code);
    header("Content-Type: application/json");
    echo json_encode(["error" => $msg]);
    exit;
}

/* ---------------------------------------------------------------- API */
if (isset($_GET["api"])) {
    $path = (string)$_GET["api"];
    if (strpos($path, "/api/") !== 0 || strpos($path, "..") !== false || preg_match('/[\r\n\s]/', $path)) {
        fs_fail(400, "bad api path");
    }
    $method = $_SERVER["REQUEST_METHOD"];
    $body = null;
    if ($method === "POST") {
        if (!fs_same_origin()) {
            fs_fail(403, "cross-origin write refused");
        }
        /* csrf-magic's automatic check is off for this request (it reads
           a form field); check the header with its own validation. */
        if (empty($_SERVER["HTTP_X_CSRFTOKEN"]) || !csrf_check_tokens((string)$_SERVER["HTTP_X_CSRFTOKEN"])) {
            fs_fail(403, "invalid CSRF token");
        }
        $body = file_get_contents("php://input");
        if (strlen($body) > 4 * 1024 * 1024) {
            fs_fail(413, "payload too large");
        }
    } elseif ($method !== "GET") {
        fs_fail(405, "method not allowed");
    }
    list($out, $code, $rh, $err) = fs_fetch($FLOWSIGHT_BASE . $path, $method, $body,
        $body !== null ? ["Content-Type: application/json"] : []);
    if ($out === null) {
        fs_fail(502, "flowsightd unreachable: " . $err);
    }
    http_response_code($code ?: 200);
    header("Content-Type: " . ($rh["content-type"] ?? "application/json"));
    if (!empty($rh["content-disposition"])) {
        header("Content-Disposition: " . $rh["content-disposition"]);
    }
    header("Cache-Control: no-store");
    echo $out;
    exit;
}

/* ---------------------------------------------------------------- assets */
if (isset($_GET["asset"])) {
    $name = (string)$_GET["asset"];
    if (!preg_match('/^[A-Za-z0-9_.\/-]+$/', $name) || strpos($name, "..") !== false) {
        fs_fail(400, "bad asset");
    }
    list($out, $code, $rh, $err) = fs_fetch($FLOWSIGHT_BASE . "/static/" . $name);
    if ($out === null || $code !== 200) {
        http_response_code(404);
        exit;
    }
    header("Content-Type: " . ($rh["content-type"] ?? "application/octet-stream"));
    header("Cache-Control: " . (strpos($name, "/") !== false ? "private, max-age=31536000, immutable" : "no-cache"));
    echo $out;
    exit;
}

/* ---------------------------------------------------------------- app shell */
if (isset($_GET["app"])) {
    list($out, $code, $rh, $err) = fs_fetch($FLOWSIGHT_BASE . "/static/index.html");
    if ($out === null || $code !== 200) {
        header("Content-Type: text/plain");
        http_response_code(502);
        echo "flowsightd is not running" . ($err ? ": " . $err : "") . "\nStart it under Status > Services or run: /usr/local/etc/rc.d/flowsight.sh start";
        exit;
    }
    $csrf = ["token" => csrf_get_tokens()];
    $hostTheme = (isset($_GET["theme"]) && in_array($_GET["theme"], ["light", "dark"], true)) ? $_GET["theme"] : "";
    /* The one inline script (the boot values) carries a per-response nonce, so
     * the policy can refuse every other inline script. */
    $nonce = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
    $boot = "<script nonce=\"" . $nonce . "\">window.FS_API_BASE='flowsight.php?api=';window.FS_CSRF=" . json_encode($csrf["token"])
        . ";window.FS_HOST_THEME=" . json_encode($hostTheme) . ";window.FS_HOST_NAV=false;</script>";
    $html = str_replace("/static/", "flowsight.php?asset=", $out);
    $html = str_replace("<head>", "<head>" . $boot, $html);
    header("Content-Type: text/html; charset=utf-8");
    header("Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-" . $nonce . "'; style-src 'self' 'unsafe-inline'; "
        . "img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'self'");
    echo $html;
    exit;
}

/* ---------------------------------------------------------------- page */
/* The page's title before the app reports its own: the menu's name for the
 * id when we know it, else the id tidied up. The app corrects it on load. */
$fsTitles = ["overview" => "Overview", "flows" => "Sessions", "apps" => "Applications", "web" => "Web", "dns" => "DNS", "paths" => "Map",
    "hosts" => "IP Addresses", "devices" => "Devices", "zones" => "Zones", "policy" => "Policies", "qos" => "Priority", "groups" => "Groups & Schedules",
    "egress" => "DLP", "tls" => "Stateful Packet Inspection", "inspect" => "Packet Inspection", "firewall" => "Firewall Analysis Engine (FAE)",
    "alerts" => "Alerting", "reports" => "Reports", "api" => "API", "setup" => "Setup", "modules" => "Settings", "system" => "Status", "events" => "Events", "findings" => "Findings"];
$pageId = isset($_GET['page']) ? strtolower(preg_replace('/[?#].*$/', '', $_GET['page'])) : 'overview';
$pageName = $fsTitles[$pageId] ?? ucfirst(preg_replace('/[^A-Za-z0-9 ]/', ' ', $pageId));
$pgtitle = [gettext("FlowSight"), $pageName];
include("head.inc");
?>
<style>
  #fs-frame { width: 100%; height: 640px; border: 0; background: transparent; border-radius: 6px; overflow: hidden; }
</style>
<div class="row">
  <div class="col-xs-12">
        <iframe id="fs-frame" data-src="flowsight.php?app=1" data-page="<?= isset($_GET['page']) ? htmlspecialchars(preg_replace('/[^A-Za-z0-9_\/?=&.:,%-]/', '', $_GET['page'])) : '' ?>"
                title="FlowSight" referrerpolicy="same-origin" scrolling="no"></iframe>
        <script>
        (function () {
          // Tell the app whether the pfSense theme around it is light or dark, from the
          // page's actual background colour, so every theme is handled.
          var f = document.getElementById('fs-frame');
          function tone() {
            var c = getComputedStyle(document.body).backgroundColor.match(/\d+(\.\d+)?/g) || [255, 255, 255];
            var l = (0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]) / 255;
            return l < 0.5 ? 'dark' : 'light';
          }
          var t = tone();
          f.src = f.dataset.src + '&theme=' + t + (f.dataset.page ? '#' + f.dataset.page : '');
          // The app reports its height; the frame follows so the pfSense page scrolls, not the frame.
          window.addEventListener('message', function (e) {
            if (e.source !== f.contentWindow || !e.data) return;
            if (e.data.fsHeight) f.style.height = Math.max(480, Math.ceil(e.data.fsHeight) + 4) + 'px';
            if (e.data.fsNav) follow(e.data.fsNav);
          });
          // The app moved to another of its pages: the breadcrumb, the tab
          // title and the address bar follow, so what the page around it
          // says matches what is on screen and a reload lands on the same
          // page (with the same route, device or filter).
          function follow(nav) {
            var title = String(nav.title || ''), group = String(nav.group || '');
            if (!title) return;
            var crumbs = document.querySelectorAll('ul.breadcrumb li, .breadcrumb li');
            if (crumbs.length) {
              var last = crumbs[crumbs.length - 1];
              var a = last.querySelector('a');
              (a || last).textContent = title;
              if (crumbs.length >= 3 && group) {
                var mid = crumbs[crumbs.length - 2];
                var ma = mid.querySelector('a');
                (ma || mid).textContent = group;
              }
            }
            var h1 = document.querySelector('.page-content-head h1, header h1');
            if (h1 && /FlowSight/.test(h1.textContent)) h1.textContent = 'FlowSight: ' + title;
            document.title = title + ' | FlowSight | ' + (document.title.split(' | ').pop() || '');
            try {
              var hash = String(nav.hash || nav.page || '');
              if (hash && window.history && history.replaceState) {
                history.replaceState(null, '', 'flowsight.php?page=' + encodeURIComponent(hash));
              }
            } catch (err) { /* address bar is optional */ }
          }
          // Report the visible slice of the frame so the app can page long
          // tables against the page's own scrollbar (there is only one).
          function reportScroll() {
            if (!f.contentWindow) return;
            var r = f.getBoundingClientRect();
            f.contentWindow.postMessage({ fsScroll: { top: Math.max(0, -r.top), height: window.innerHeight } }, location.origin);
          }
          var st = null;
          window.addEventListener('scroll', function () { if (!st) st = setTimeout(function () { st = null; reportScroll(); }, 100); }, { passive: true });
          window.addEventListener('resize', reportScroll);
          f.addEventListener('load', function () { setTimeout(reportScroll, 200); });

          var mq = window.matchMedia('(prefers-color-scheme: dark)');
          function push() { var n = tone(); if (n !== t) { t = n; f.contentWindow.postMessage({ fsTheme: t }, location.origin); } }
          if (mq.addEventListener) mq.addEventListener('change', function () { setTimeout(push, 100); });
          new MutationObserver(function () { setTimeout(push, 100); }).observe(document.body, { attributes: true, attributeFilter: ['class', 'data-theme', 'style'] });
        })();
        </script>
  </div>
</div>
<?php include("foot.inc"); ?>
