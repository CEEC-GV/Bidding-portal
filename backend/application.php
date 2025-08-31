<?php

  date_default_timezone_set("Asia/Kolkata");

  class application {
    private $action        = 'LOADPAGE';
    private $dbconnection  = null;
    private $response      = array();
    private $userid        = null;
    private $usertype      = null;
    private $userlevel     = 'NA';
    private $mandateid     = null;
    private $userstamp     = null;
    private $encryptfields = array();
    private $encryptmethod = 'AES-128-CTR';
    private $encryptkey    = 'fKm9gmLqvpFoHMnt';
    private $iv            = '1234567891011121';

    public
    function __construct($action = null) {
      if ((isset($_SERVER['REQUEST_URI'])) && (strpos($_SERVER['REQUEST_URI'], 'cfcallback') !== false)) {
        $this->action = 'CFCALLBACK';
      }
      else if ((isset($_SERVER['REQUEST_URI'])) && (strpos($_SERVER['REQUEST_URI'], 'downloadreport') !== false)) {
        $this->action = 'DOWNLOADREPORT';
      }
      else if ((isset($_SERVER['REQUEST_URI'])) && (strpos($_SERVER['REQUEST_URI'], 'download') !== false)) {
        $this->action = 'DOWNLOAD';
      }
      else if (isset($_GET['action']))
        $this->action = strtoupper($_GET['action']);
      else if (isset($_POST['action']))
        $this->action = $_POST['action'];

      //$this->encryptfields['users'] = array("email", "phonenumber");
      $this->encryptfields['bids'] = array("bidquantity", "bidprice");
    }

    private
    function respond() {
      if (!isset($this->response['status']))
        $this->response['status'] = 'failure';
      if (isset($this->usertype))
        $this->response['usertype'] = $this->usertype;
      if (isset($this->userid))
        $this->response['userid'] = $this->userid;
      if ($this->usertype == 'admin' || (true)) {
        $data = file_get_contents('../inc/display.json');
        //$data = file_get_contents('display.json');
        $info = json_decode($data, true);
        if ((is_array($info)) && (count($info) > 0)) {
          $this->response['display'] = $info;
        }
      }

      if (isset($_POST['mandateid'])) {
        $this->mandateid = $_POST['mandateid'];
      }
      //$this->response['version'] = $this->version;

      header('Access-Control-Allow-Origin: *');
      header('Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS, post, get');
      header("Access-Control-Max-Age", "3600");
      header('Access-Control-Allow-Headers: Origin, Content-Type, X-Auth-Token');
      header("Access-Control-Allow-Credentials", "true");

      printf("%s", json_encode($this->response));
    }

    private
    function log($value) {
      error_log(print_r($value, true));
    }

    private
    function encrypt($value) {
      $value = json_encode($value);
      return openssl_encrypt($value, $this->encryptmethod, $this->encryptkey, 0, $this->iv);
    }

    private
    function decrypt($value) {
      $data = openssl_decrypt($value, $this->encryptmethod, $this->encryptkey, 0, $this->iv);
      if ($this->isjson($data)) {
        $data = json_decode($data, true);
        return $data;
      }
      return null;
    }

    //
    // Encrypt data with symmetric key.
    //
    protected
    function symmetricencrypt($value) {
      if (is_array($value)) {
        $value = json_encode($value);
      }
      $ciphertext = openssl_encrypt($value, 'aes-128-cbc', $this->encryptkey, true, $this->iv);
      return base64_encode($ciphertext);
    }

    //
    // Decrypt data with symmetric key.
    //
    protected
    function symmetricdecrypt($data) {
      $message = base64_decode($data);
      if ($message === false) {
        return FAILURE;
      }

      $cookiedata = openssl_decrypt($message, 'aes-128-cbc', $this->encryptkey, true, $this->iv);
      return $cookiedata;
    }

    private
    function mkdir($path) {
       return is_dir($path) || mkdir($path);
    }

    /**
    * Returns true, when the given parameter is a valid JSON string.
    */
    private
    function isjson( $value ) {
     // Numeric strings are always valid JSON.
     if ( is_numeric( $value ) ) { return true; }

     // A non-string value can never be a JSON string.
     if ( ! is_string( $value ) ) { return false; }

     // Any non-numeric JSON string must be longer than 2 characters.
     if ( strlen( $value ) < 2 ) { return false; }

     // "null" is valid JSON string.
     if ( 'null' === $value ) { return true; }

     // "true" and "false" are valid JSON strings.
     if ( 'true' === $value ) { return true; }
     if ( 'false' === $value ) { return true; }

     // Any other JSON string has to be wrapped in {}, [] or "".
     if ( '{' != $value[0] && '[' != $value[0] && '"' != $value[0] ) { return false; }

     // Verify that the trailing character matches the first character.
     $last_char = $value[strlen($value) -1];
     if ( '{' == $value[0] && '}' != $last_char ) { return false; }
     if ( '[' == $value[0] && ']' != $last_char ) { return false; }
     if ( '"' == $value[0] && '"' != $last_char ) { return false; }

     // See if the string contents are valid JSON.
     return null !== json_decode( $value );
    }

    protected
    function clean($string) {
      $string = str_replace(' ', '', $string); // Replaces all spaces with hyphens.
      return preg_replace('/[^A-Za-z0-9\-]/', '', $string); // Removes special chars.
    }

    protected
    function setcookie($name, $value, $encrypted = true) {
      if ($encrypted)
        $cookiedata = openssl_encrypt($value, 'aes-256-cbc', 'rider', true, '1234567890986543');
      else
        $cookiedata = $value;

      return setcookie($name, $cookiedata, time()+3600*24*1000 , "/", null, true, false);
    }


    private
    function authenticate() {
      if ((isset($_POST['login'])) || (isset($_GET['login']))) {
        $logincookie = '';
      	if (isset($_POST['login'])) $logincookie = urldecode($_POST['login']);
      	else if (isset($_GET['login'])) $logincookie = urldecode($_GET['login']);
        $cookiedata = openssl_decrypt($logincookie, 'aes-256-cbc', 'bpcl', true, '1234567890986543');
        if (isset($cookiedata)) {
          $cookiedata = json_decode($cookiedata, true);
          if ((isset($cookiedata)) && (count($cookiedata) > 0) && (isset($cookiedata['id']))) {
            $userid = $cookiedata['id'];
            $users = $this->dbquery(sprintf("select * from users where id=%s", $userid));
            if ((isset($users)) && (is_array($users)) && (count($users) > 0) && (isset($users[0]['status']))) {
              $userinfo        = $users[0];
              $this->userid    = $userinfo['id'];
              $this->userstamp = $userinfo['createdat'];
              $this->usertype  = strtolower($userinfo['type']);
              $this->userlevel = strtolower($userinfo['level']);

              $cachedata = array();
              $cachedata['id']           = $userinfo['id'];
              $cachedata['username']     = $userinfo['username'];
              $cachedata['employeeid']   = $userinfo['employeeid'];
              $cachedata['type']         = $userinfo['type'];
              $cachedata['level']        = $userinfo['level'];
              $cachedata['status']       = $userinfo['status'];
              $cachedata['message']      = $userinfo['message'];
              $cachedata['alertpointer'] = (isset($userinfo['alertpointer'])) ?  $userinfo['alertpointer'] : 0;
              if (isset($userinfo['alertpointer'])) {
                $cachedata['alertpointer'] = $userinfo['alertpointer'];
              }
              $this->response['userinfo'] = $cachedata;
              if (strtolower($userinfo['status']) == 'approved') {
                if ((isset($_POST['useralertpointer'])) && (is_numeric($_POST['useralertpointer']))) {
                  $oldpointer = 0;
                  $newpointer = $_POST['useralertpointer'];
                  if ((isset($userinfo['alertpointer'])) && (is_numeric($userinfo['alertpointer']))) {
                    $oldpointer = $userinfo['alertpointer'];
                  }
                  if (($oldpointer >= 0) && ($newpointer > 0) && ($newpointer > $oldpointer)) {
                    $pointerdata = array('alertpointer' => $newpointer);
                    $query = sprintf("update users set alertpointer=%s where id=%s", $newpointer, $userinfo['id']);
                    $this->dbquery($query);
                  }
                }
                return true;
              }
            }
          }
        }
      }
      $this->response['deletecookie'] = 'true';
      return false;
    }

    private
    function dbinit() {
      $this->dbconnection = new mysqli('localhost', 'root', 'general', 'bpcl');
      //$this->dbconnection = new mysqli('localhost', 'u285188420_root', 'G3n3ral@123', 'u285188420_bpcl');
      mysqli_set_charset($this->dbconnection, "utf8");
      return true;
    }

    private
    function dbquery($query) {
      $query = trim($query);
      $result = $this->dbconnection->query($query);
      if ($result == FALSE) {
        $this->log(mysqli_error($this->dbconnection));
        return false;
      }
      else {
        if (((preg_match('/^select/i', $query)) || (preg_match('/^show/i', $query)))) {
          $rows = array();
          while ($row = $result->fetch_assoc()) {
            $rows[] = $row;
          }
          return $rows;
        }
        else if ((preg_match('/^insert/i', $query))) {
          return $this->dbconnection->insert_id;
        }
        else
          return $result;
      }
    }

    private
    function deleteentry($table, $condition) {
      if ((isset($table)) && (isset($condition)) && (strlen($condition) > 0)) {
        $query = sprintf("delete from %s where %s", $table, $condition);
        return $this->dbquery($query);
      }
    }

    private
    function updateentry($table, $data, $condition, $objectid) {
      if ((isset($table)) && (is_array($data)) && (count($data) > 0)) {
        $values = '';
        $count = 1;
        foreach ($data as $field => $value) {
          $value = trim($value);
	        $value = $this->dbconnection->real_escape_string($value);
	        if (($value == '') || strlen($value) == 0)
            $value = 'null';
	        else
            $value = "'". $value. "'";
          if ($count == 1) {
            $values = sprintf("%s = %s", $field, $value);
          }
          else {
            $values = sprintf("%s, %s = %s", $values, $field, $value);
          }
          $count++;
        }
        $query = sprintf("update %s set %s where %s", $table, $values, $condition);
        $res = $this->dbquery($query);
        if (($res != false) && ($table != 'logs') && ($table != 'hidefields')) {
          $this->setlogs($table, $objectid, 'UPDATE', $data);
        }
        return $res;
      }
    }

    private
    function buildinsertquery($table, $data, $append = false) {
      if ((isset($table)) && (is_array($data)) && (count($data) > 0)) {
        $fields = '';
        $values = '';
        $count = 1;
        foreach ($data as $field => $value) {
          $value = trim($value);
      	  $value = $this->dbconnection->real_escape_string($value);
	        if (($value == '') || strlen($value) == 0)
            $value = 'null';
	        else
            $value = "'". $value. "'";
          if ($count == 1) {
            $fields = sprintf("%s", $field);
            $values = sprintf("%s", $value);
          }
          else {
            $fields = sprintf("%s, %s", $fields, $field);
            $values = sprintf("%s, %s", $values, $value);
          }
          $count++;
        }
        if ($append) {
          return $values;
        }
        $query = sprintf("insert into %s(%s) values(%s)", $table, $fields, $values);
        return $query;
      }
    }

    private
    function createentry($table, $data) {
      if ((isset($table)) && (is_array($data)) && (count($data) > 0)) {
        $fields = '';
        $values = '';
        $count = 1;
        if (isset($this->encryptfields[$table])) {
          foreach ($this->encryptfields[$table] as $field) {
            if (isset($data[$field])) {
              //$data[$field] = $this->encrypt($data[$field]);
            }
          }
        }

        foreach ($data as $field => $value) {
          $value = trim($value);
      	  $value = $this->dbconnection->real_escape_string($value);
	        if (($value == '') || strlen($value) == 0)
            $value = 'null';
	        else
            $value = "'". $value. "'";
          if ($count == 1) {
            $fields = sprintf("%s", $field);
            $values = sprintf("%s", $value);
          }
          else {
            $fields = sprintf("%s, %s", $fields, $field);
            $values = sprintf("%s, %s", $values, $value);
          }
          $count++;
        }
        //$query = sprintf("insert into %s(%s) values(%s)", $table, $fields, $values);
        $query = $this->buildinsertquery($table, $data);
        $res = $this->dbquery($query);
        if (($res != false) && ($table != 'logs') && ($table != 'hidefields')) {

          if ((!isset($this->userid)) && ($table == 'users')) {
            $this->userid = $res;
          }

          $this->setlogs($table, $res, 'CREATE', $data);
        }
        return $res;
      }
    }

    private
    function getMaximumFileUploadSize() {
      return min(ini_get('post_max_size'), ini_get('upload_max_filesize'));
    }

    private
    function mediaupload() {
      $filetype = array('pdf','jpeg','jpg','png','gif','PNG','JPEG','JPG');
      $qrcode   = false;
      if ((isset($_POST['qrcode'])) && ($_POST['qrcode'] == 'true')) $qrcode = true;
      $this->mkdir('../inc/media');
      foreach ($_FILES as $key) {
        $convert =  preg_replace('/\s+/', '_', $key['name']);
        $name = time()."_".$convert;
        $name = $convert;
        $path='../inc/media/'.$name;
        $file_ext = pathinfo($name, PATHINFO_EXTENSION);
        if (in_array(strtolower($file_ext), $filetype)) {
          if ((isset($_POST['ignoreext'])) && ($_POST['ignoreext'] == 'true')) {
            $filename = pathinfo($name, PATHINFO_FILENAME);
            $path='../inc/media/'.$filename;
          }
          if ($key['size'] < 10000000) {
            $res = @move_uploaded_file($key['tmp_name'], $path);
            if ($res) {
              $this->response['status']   = 'success';
              $this->response['filepath'] = $name;
            }
          }
          else {
            $this->response['error'] = 'FILE_SIZE_ERROR';
          }
        }
        else {
          $this->response['error'] = 'FILE_TYPE_ERROR';
        }
      }
      if (!isset($this->response['status'])) {
        $this->response['status']   = 'success';
        $this->response['filepath'] = 'images/';
      }
    }

    private
    function logout() {
      if ($this->deletecookie('login')) {
        $this->response['status']  = 'success';
      }
    }

    private
    function encode_utf8($data) {
      if ($data === null || $data === '') {
        return $data;
      }
      if (!mb_check_encoding($data, 'UTF-8')) {
        return mb_convert_encoding($data, 'UTF-8');
      } else {
        return $data;
      }
    }

    private
    function view() {
      if (($this->usertype == 'admin') && (isset($_GET['file']))) {
        $filepath = sprintf("../inc/media/%s", $_GET['file']);
        if ((file_exists($filepath))) {
          if ((file_exists($filepath)) && ($fd = fopen($filepath, "r"))) {
            $fsize      = filesize($filepath);
            $path_parts = pathinfo($filepath);
            $ext        = ' ';//strtolower($path_parts["extension"]);
            $file       = explode($ext, $path_parts['basename']);
            $name       = substr($file[0], 0, -1);
            $filename   = $name. "." .$ext;
            $mimetype   = mime_content_type($filepath);
            $type       = $mimetype;
            header("Content-type: ". $type. "");
            if ((isset($this->fileaction)) && ($this->fileaction == 'd'))
              header("Content-Disposition: attachment; filename=\"".$filename."\"");
            header("Content-length: $fsize");
            header("Cache-control: private");
            fpassthru($fd);
          }
        }
      }
    }

    private
    function download() {
      if (isset($_GET['file'])) {
        $file = $_GET['file'];
        if ((file_exists($file))) {
          header("Content-Description: File Transfer");
          header("Content-Type: application/octet-stream");
          header("Content-Disposition: attachment; filename=\"". basename($file) ."\"");
          readfile ($file);
          exit();
        }
      }
    }

    private
    function downloadreport() {
      if ((isset($_GET['type']))) {
        $stamp = time();
        $type = $_GET['type'];
        include_once '../inc/SimpleXLSXGen.php';
        date_default_timezone_set("Asia/Kolkata");

        $query = sprintf("select * from mandates");
        $data  = $this->dbquery($query);
        if ((isset($data)) && (is_array($data)) && (count($data))) {
          $newdata = array();
          $count = 0;
          foreach($data[0] as $index => $value) {
            if (!isset($newdata[$count])) {
              $newdata[$count] = array();
            }
            $newdata[$count][$index] = $index;
          }
          foreach($data as $index => $value) {
            $newdata[] = $value;
          }
          if ($type == 'excel') {
        	  $file = sprintf("report%s.xlsx", time());
            $xlsx = SimpleXLSXGen::fromArray($newdata);
            $status = $xlsx->downloadAs($file);
            exit;
          }
          else if ($type == 'csv') {
            $fp = fopen('php://output', 'w');
            header('Content-Type: text/csv');
            header('Content-Disposition: attachment; filename="report'.$stamp.'.csv"');
            header('Pragma: no-cache');
            header('Expires: 0');

            $headers = array();
            foreach($data[0] as $index => $value) {
               $headers[] = $index;
            }

            if ($fp) {
              fputcsv($fp, $headers);
              foreach($data as $index => $value) {
                fputcsv($fp, $value);
              }
            }
            exit;
          }
          else if ($type == 'pdf') {
            include_once '../inc/pdf/fpdf.php';

            $pdf = new FPDF();

            $pdf->AddPage();
            $pdf->SetFont('Arial', '', 10);

            $header = $data[0];

            $pdf->SetFont('Arial', 'B', 10);
            $pdf->Cell(0, 10, 'Report', 0, 1, 'C');

            foreach($header as $col => $val) {
              $pdf->Cell(40, 7, $col, 1);
            }
            $pdf->ln(10);

            $pdf->SetFont('Arial', '', 10);

            foreach($data as $row) {
              foreach($row as $col) {
                $pdf->Cell(40, 6, $col, 1);
              }
              $pdf->Ln();
            }

            $pdf->Output();
            exit;
            $pdf->AddPage();
            $pdf->SetFont('Arial','B',16);

            $array1= array(1,2,3);
            $array2= array('apple', "ball", "cat");

            $pdf->Cell(40,10,'Numbers');
            $pdf->Cell(40,10,'Animals');
            $pdf->Ln(10);
            foreach($array1 as $key=>$row){
              $pdf->Cell(40,10,$row);
              $pdf->Cell(40,10,$array2[$key]);
              $pdf->Ln(10);
           }
           $pdf->Output();
            //header('Content-Type: application/pdf');
            //$fp = fopen( $_SERVER['DOCUMENT_ROOT'] . 'report.pdf', 'wb' );
            //fwrite( $fp, $data);
            //fclose( $fp );
          }
        }
      }
    }

    private
    function loadpage() {
      $page  = file_get_contents("index.html");
      printf("%s", $page);
    }

    private
    function register() {
      if ((isset($_POST['type'])) && (isset($_POST['data'])) && ($this->isjson($_POST['data']))) {
        $type = $_POST['type'];
        $data = json_decode($_POST['data'], true);
        if ((isset($data['email'])) && (isset($data['password']))) {
          $email    = trim($data['email']);
          $password = $this->symmetricdecrypt(trim($data['password']));
          if (strlen($password) >= 6) {
            $cookiedata = array();
            $password   = hash('sha256', $password);

            $query = sprintf("select * from users where email = '%s' and password = '%s'", $email, $password);
            //$query = sprintf("select * from users where email = '%s'", $email);
            $users = $this->dbquery($query);
            if ((isset($users)) && (is_array($users)) && (count($users) >= 0)) {
              if ($type == 'login') {
                if (count($users) > 0) {
                  $userinfo = $users[0];
                  $cookiedata = array();
                  $cookiedata['id']           = $userinfo['id'];
                  $cookiedata['username']     = $userinfo['username'];
                  $cookiedata['type']         = $userinfo['type'];
                  $cookiedata['level']        = $userinfo['level'];
                  $cookiedata['status']       = $userinfo['status'];
                  $cookiedata['message']      = $userinfo['message'];
                  $cookiedata['alertpointer'] = (isset($userinfo['alertpointer'])) ?  $userinfo['alertpointer'] : 0;
                }
                else {
                  $this->response['status']  = 'failure';
                  $this->response['error']   = 'Incorrect username / password';
                  return 'failure';
                }
              }
              else if ($type == 'register') {
                $stamp = time();
                $data['createdat']  = $stamp;
                $data['modifiedat'] = $stamp;
                $data['password'] = $password;
                $res = $this->createentry('users', $data);
                if ($res != false) {
                  $cookiedata['id']       = $res;
                  $cookiedata['username'] = $data['username'];
                  $cookiedata['type']     = (isset($data['type'])) ? $data['type'] : 'CUSTOMER';
                  $cookiedata['status']   = 'pending';
                }
              }
            }
            if ((is_array($cookiedata)) && (count($cookiedata) > 0)) {
              if (isset($cookiedata['password'])) unset($cookiedata['password']);
              $cookie = openssl_encrypt(json_encode($cookiedata), 'aes-256-cbc', 'bpcl', true, '1234567890986543');
              $this->response['status']   = 'success';
              $this->response['login']    = urlencode($cookie);
              $this->response['data']     = $cookiedata;
              $this->response['userinfo'] = $cookiedata;
            }
          }
          else {
            $this->response['status']  = 'failure';
            $this->response['error']   = 'Password should be atleast 6 characters';
            return 'failure';
          }
        }
      }
    }

    private
    function resetpassword() {
      if ($_POST['password']) {
        $password = trim($_POST['password']);
        if (strlen($password) >= 6) {
          $password = hash('sha256', $password);
          $error = '';
          if ((isset($_POST['currentpassword'])) && (isset($this->userid))) {
            $cpassword = trim($_POST['currentpassword']);
            $cpassword = hash('sha256', $cpassword);
            $query = sprintf("select * from users where id=%s and password='%s'", $this->userid, $cpassword);
            $error = 'Please enter correct current password';
          }
          if (isset($query)) {
            $res = $this->dbquery($query);
            if ((isset($res)) && (is_array($res)) && (count($res) > 0)) {
              $query = sprintf("update users set password='%s' where id=%s", $password, $res[0]['id']);
              $status = $this->dbquery($query);
              if ($status != false) {
                $this->response['status']  = 'success';
              }
            }
            else {
              $this->response['status']  = 'failure';
              $this->response['error']   = $error;
              return 'failure';
            }
          }
        }
      }
    }

    private
    function generatemandatekey() {
      $stamp = time();
      $key   = '';
      $year  = date('Y', $stamp);
      $month = date('m', $stamp);
      if ($month > 3) {
        $year++;
      }
      $sl = 0;
      $query = sprintf("select id from mandates order by id desc limit 1");
      $res = $this->dbquery($query);
      if ((isset($res)) && (is_array($res)) && (count($res) >= 0)) {
        if ((count($res) > 0) && (isset($res[0]['id']))) {
          $sl = $res[0]['id'];
        }
        $sl++;
        $key = sprintf("%s%s%06s-00", $year, $month, $sl);
      }
      return $key;
    }

    private
    function randomnumber($object, $field, $length = 12) {
      //$randnum = rand(1000000000,9999999999);
      $number = '1234567890';
      $numberlength = strlen($number);
      $randnum = '';
      for ($i = 0; $i < $length; $i++) {
        $randnum .= $number[rand(0, $numberlength - 1)];
      }

      $query = sprintf("select id from %s where %s='%s'", $object, $field, $randnum);
      $res = $this->dbquery($query);
      if ((isset($res)) && (is_array($res)) && (count($res) == 0)) {
        return $randnum;
      }
      else
        return $this->randomnumber($object, $field, $length);
    }

    private
    function mandateaction() {
      if (($this->usertype == 'masteradmin') || (($this->usertype == 'admin') && ($this->userlevel == 'l2'))) {
        if ((isset($_POST['object'])) && (isset($_POST['objectid'])) && (isset($_POST['useraction'])) && ($this->isjson($_POST['useraction']))) {
          $object = $_POST['object'];
          $data = json_decode($_POST['useraction'], true);
          //$action = strtolower($_POST['useraction']);
          //if ($action == 'approve') {
          //  $data['status'] = 'APPROVED';
          //}
          //else if ($action == 'reject') {
          //  $data['status'] = 'REJECTED';
          //}
          if (count($data) > 0) {
            $res = $this->updateentry($object, $data, sprintf("id=%s and status = 'PENDING'", $_POST['objectid']), $_POST['objectid']);
            if ($res != false) {
              $this->response['status'] = 'success';
            }
          }
        }
      }
    }

    private
    function update() {
      if ((isset($_POST['object'])) && (isset($_POST['objectid'])) && (isset($_POST['data'])) && ($this->isjson($_POST['data']))) {
        $data = json_decode($_POST['data'], true);
        if ((isset($data)) && (is_array($data)) && (count($data) > 0)) {
          $object    = $_POST['object'];
          $objectid  = $_POST['objectid'];
          $stamp = time();

          $olddata = $this->dbquery(sprintf("select * from %s where id=%s", $object, $objectid));
          if ((isset($olddata)) && (is_array($olddata)) && (count($olddata) > 0)) {
            $olddata = $olddata[0];
            $hasaccess = false;
            if ($object == 'mandates') {
              if ($olddata['creator'] == $this->userid) {
                $hasaccess = true;
              }
            }
            else if ($object == 'users') {
              if ($olddata['id'] == $this->userid) {
                $hasaccess = true;
              }
              else if ($this->usertype == 'masteradmin') {
                $hasaccess = true;
              }
            }
            else if ($object == 'bids') {
              if ($olddata['creator'] == $this->userid) {
                $hasaccess = true;
              }
            }
            if ($hasaccess) {
              $data['modifiedat'] = $stamp;
              if (($object == 'mandates') && (isset($olddata['mandatekey']))) {
                $oldkey = explode('-', $olddata['mandatekey']);
                if ((isset($oldkey)) && (count($oldkey) == 2)) {
                  if ($oldkey[1] < 99) {
                    $version = $oldkey[1] + 1;
                    $newkey  =  sprintf("%s-%02s", $oldkey[0], $version);
                    $data['mandatekey'] = $newkey;
                    $data['status']     = 'PENDING';
                  }
                  else {
                    $this->response['status'] = 'failure';
                    $this->response['error']  = 'modification limit exceeded';
                    return 'failure';
                  }
                }
              }
              $res = $this->updateentry($object, $data, sprintf("id=%s", $objectid), $objectid);
              if ($res != false) {
                $this->response['status'] = 'success';
              }
            }
          }
        }
      }
    }

    private
    function create() {
      if ((isset($_POST['object'])) && (isset($_POST['data'])) && ($this->isjson($_POST['data']))) {
        $data = json_decode($_POST['data'], true);
        if ((isset($data)) && (is_array($data)) && (count($data) > 0)) {
          $operation = 'new';
          $object    = $_POST['object'];
          $hasaccess = false;
          if ($object == 'bids') {
            if ($this->usertype == 'customer') {
              $hasaccess = true;
            }
          }
          elseif ($object == 'mandates') {
            if (($this->usertype == 'admin') && ($this->userlevel == 'l1')) {
              $hasaccess = true;
            }
          }
          if ($hasaccess) {
            $stamp = time();
            if ($operation == 'new') {
              $data['creator']    = $this->userid;
              $data['createdat']  = $stamp;
              $data['modifiedat'] = $stamp;
              if ($object == 'mandates') {
                $field = 'mandatekey';
                //$randomnumber = $this->randomnumber($object, $field);
                $mandatekey = $this->generatemandatekey();
                if ($mandatekey != '') {
                  $data[$field]  = $mandatekey;
                }
                else {
                  $this->response['status'] = 'failure';
                  return 'failure';
                }
              }

              $res = $this->createentry($object, $data);
              if ($res != false) {
                if (($object == 'bids') && (isset($data['mandateid']))) {
                  $this->setaccess($data['mandateid']);
                }
                $this->response['status'] = 'success';
              }
            }
            else {
              $this->response['status'] = 'failure';
              $this->response['error']  = 'Invalid operation';
              return 'failure';
            }
          }
          else {
            $this->response['status'] = 'failure';
            $this->response['error']  = 'No access';
            return 'failure';
          }
        }
      }
    }

    private
    function loaddata() {
      if ((isset($_POST['object'])) && (isset($_POST['objectid']))) {
        $object   = $_POST['object'];
        $objectid = $_POST['objectid'];
        $hasaccess = true;
        if ($hasaccess) {
          if ($this->usertype == 'masteradmin') {
            $query = sprintf("select * from %s where id=%s", $object, $objectid);
          }
          else if ($object == 'mandates') {
            if ($this->usertype == 'customer') {
              $query = sprintf("select * from %s where id=%s and (status = 'APPROVED' or access like '%%-%s-%%')", $object, $objectid, $this->userid);
            }
            if ($this->usertype == 'admin') {
              if ($this->userlevel == 'l2') {
                $query = sprintf("select * from %s where id=%s", $object, $objectid);
              }
              else if ($this->userlevel == 'l1') {
                $query = sprintf("select * from %s where id=%s and creator = %s", $object, $objectid, $this->userid);
              }
            }
          }
          else if ($object == 'users') {
            if ($this->usertype == 'admin') {
              $query = sprintf("select * from %s where id=%s", $object, $objectid);
            }
            else {
              $query = sprintf("select * from %s where id=%s and id = %s", $object, $objectid, $this->userid);
            }
          }
          else if ($object == 'bids') {
            if (($this->usertype == 'admin') || ($this->usertype == 'masteradmin')) {
              $query = sprintf("select * from %s where id=%s", $object, $objectid);
            }
            else if (($this->usertype == 'customer')) {
              $query = sprintf("select * from %s where id=%s and creator=%s", $object, $objectid, $this->userid);
            }
          }
          if (isset($query)) {
            $res = $this->dbquery($query);
            if ((isset($res)) && (is_array($res)) && (count($res) > 0)) {
              $this->response['status'] = 'success';
              $this->response['data']   = $res[0];
              if (($object == 'mandates') && ($this->usertype == 'customer')) {
                $query = sprintf("select * from bids where mandateid=%s and creator=%s", $objectid, $this->userid);
                $bids = $this->dbquery($query);
                if ((isset($bids)) && (is_array($bids)) && (count($bids) > 0)) {
                  $this->response['userbid'] = $bids[0];
                }

                $newdata = $res[0];
                $query = sprintf("select * from hidefields where object='%s' and objectid=%s", $object, $objectid);
                $hidefields = $this->dbquery($query);
                if ((isset($hidefields)) && (is_array($hidefields)) && (count($hidefields) > 0) &&
                    (isset($hidefields[0]['fields'])) && ($this->isjson($hidefields[0]['fields']))) {
                  $fields = json_decode($hidefields[0]['fields'], true);
                  if ((isset($fields)) && (is_array($fields)) && (count($fields) > 0)) {
                    foreach ($fields as $field) {
                      if (isset($newdata[$field])) {
                        $newdata[$field] = '';
                      }
                    }
                  }
                }
                $this->response['data'] = $newdata;
              }
              else if (($object == 'mandates') && (isset($res[0]['creator'])) && ($res[0]['creator'] == $this->userid)) {
                $query = sprintf("select * from hidefields where object='%s' and objectid=%s", $object, $objectid);
                $hidefields = $this->dbquery($query);
                if ((isset($hidefields)) && (is_array($hidefields)) && (count($hidefields) > 0) &&
                    (isset($hidefields[0]['fields'])) && ($this->isjson($hidefields[0]['fields']))) {
                  $this->response['hidefields'] = $hidefields[0]['fields'];
                }
              }
            }
          }
          else {
            $this->response['status'] = 'failure';
            $this->response['error']  = 'No access';
            return 'failure';
          }
        }
        else {
          $this->response['status'] = 'failure';
          $this->response['error']  = 'No access';
          return 'failure';
        }
      }
    }

    private
    function loadlist() {
      if ((isset($_POST['object']))) {
        $operands = array("greaterthanequalto" => ">=", "greaterthan" => ">", "lesserthanequalto" => "<=", "lesserthan" => "<", "equalto" => "=", "notequalto" => "!=");
        $object = $_POST['object'];
        $hasaccess = true;
        if ($hasaccess) {
          $limit1     = 0;
          $limit2     = 20;
          $orderfield = 'id';
          $ordertype  = 'DESC';
          if ((isset($_POST['limit1'])) && (is_numeric($_POST['limit1'])) && ($_POST['limit1'] > 0)) {
            $limit1 = $_POST['limit1'];
          }
          if ((isset($_POST['limit2'])) && (is_numeric($_POST['limit2'])) && ($_POST['limit2'] > 0)) {
            $limit2 = $_POST['limit2'];
          }
          if ((isset($_POST['sort'])) && ($this->isjson($_POST['sort']))) {
            $sort = json_decode($_POST['sort'], true);
            if ((isset($sort)) && (isset($sort['field'])) && (isset($sort['type']))) {
              $orderfield = $sort['field'];
              $ordertype  = $sort['type'];
            }
          }
          $condition = '';
          if ($object == 'mandates') {
            if ($this->usertype == 'customer') {
              $condition = sprintf("(status = 'APPROVED' or access like '%%-%s-%%')", $this->userid);
            }
            else if ($this->usertype == 'masteradmin') {
              $condition = sprintf("id > 0");
            }
            else if ($this->usertype == 'admin') {
              if ($this->userlevel == 'l1') {
                $condition = sprintf("creator = %s", $this->userid);
              }
              else if ($this->userlevel == 'l2') {
                $condition = sprintf("id > 0");
              }
            }
          }
          else if ($object == 'users') {
            if (($this->usertype == 'masteradmin')) {
              $condition = sprintf("id > 0");
            }
            else if ($this->usertype == 'admin') {
              $condition = sprintf(" type != 'masteradmin' ");
            }
          }
          else if ($object == 'bids') {
            if (($this->usertype == 'admin') || ($this->usertype == 'masteradmin')) {
              $condition = sprintf("id > 0");
            }
            else if (($this->usertype == 'customer')) {
              $condition = sprintf("creator = %s", $this->userid);
            }
          }
          if ($condition != '') {
            if ((isset($_POST['filter'])) && ($this->isjson($_POST['filter']))) {
              $fltrcond = '';
              $filter = json_decode($_POST['filter'], true);
              for ($i = 0; $i < count($filter); $i++) {
                $fltr = $filter[$i];
                if ((isset($fltr['field'])) && (isset($fltr['operand'])) && (isset($fltr['value']))) {
                  $operand = (isset($operands[$fltr['operand']])) ? $operands[$fltr['operand']] : '=';
                  $fieldvalue = $fltr['value'];
                  if (!is_numeric($fieldvalue)) {
                    $fieldvalue = sprintf("'%s'", $fieldvalue);
                  }
                  if ($fltrcond == '') {
                    $fltrcond = sprintf(" %s %s %s", $fltr['field'], $operand, $fieldvalue);
                  }
                  else {
                    $fltrcond = sprintf(" %s and %s %s %s", $fltrcond, $fltr['field'], $operand, $fieldvalue);
                  }
                }
              }
              if ($fltrcond != '') {
                $condition = sprintf("%s and %s", $condition, $fltrcond);
              }
            }
            if ((isset($_POST['statefilter'])) && ($this->isjson($_POST['statefilter']))) {
              $fltrcond = '';
              $statefilter = json_decode($_POST['statefilter'], true);
              foreach ($statefilter as $ind => $val) {
                if ($val == '1') {
                  if ($fltrcond == '') {
                    $fltrcond = sprintf(" status = '%s'", $ind);
                  }
                  else {
                    $fltrcond = sprintf(" %s or status = '%s'", $fltrcond, $ind);
                  }
                }
              }
              if ($fltrcond != '') {
                $condition = sprintf("%s and (%s)", $condition, $fltrcond);
              }
            }
            if ((isset($_POST['typefilter'])) && ($this->isjson($_POST['typefilter']))) {
              $fltrcond = '';
              $typefilter = json_decode($_POST['typefilter'], true);
              foreach ($typefilter as $ind => $val) {
                if ($val == '1') {
                  if ($fltrcond == '') {
                    $fltrcond = sprintf(" type = '%s'", $ind);
                  }
                  else {
                    $fltrcond = sprintf(" %s or type = '%s'", $fltrcond, $ind);
                  }
                }
              }
              if ($fltrcond != '') {
                $condition = sprintf("%s and (%s)", $condition, $fltrcond);
              }
            }
            $query = sprintf("select * from %s where %s order by %s %s limit %s,%s", $object, $condition, $orderfield, $ordertype, $limit1, $limit2);
            $countquery = sprintf("select count(id) as count from %s where %s ", $object, $condition);
          }
          else {
            $this->response['status'] = 'success';
            $this->response['data']   = array();
            return 'failure';
          }
          $countres = $this->dbquery($countquery);
          if ((isset($countres)) && (is_array($countres)) && (count($countres) > 0)) {
            $res = $this->dbquery($query);
            if ((isset($res)) && (is_array($res)) && (count($res) > 0)) {
              $this->response['status'] = 'success';
              $this->response['data']   = $res;
              if ($this->usertype == 'customer') {
                $newdata = array();
                foreach ($res as $item) {
                  $newitem = $item;
                  $query = sprintf("select * from hidefields where object='%s' and objectid=%s", $object, $item['id']);
                  $hidefields = $this->dbquery($query);
                  if ((isset($hidefields)) && (is_array($hidefields)) && (count($hidefields) > 0) &&
                      (isset($hidefields[0]['fields'])) && ($this->isjson($hidefields[0]['fields']))) {
                    $fields = json_decode($hidefields[0]['fields'], true);
                    if ((isset($fields)) && (is_array($fields)) && (count($fields) > 0)) {
                      foreach ($fields as $field) {
                        if (isset($newitem[$field])) {
                          $newitem[$field] = '';
                        }
                      }
                    }
                  }
                  $newdata[] = $newitem;
                }
                $this->response['data'] = $newdata;
              }
              $this->response['count']  = $countres[0]['count'];
            }
          }
        }
        else {
          $this->response['status'] = 'failure';
          $this->response['error']  = 'No access';
          return 'failure';
        }
      }
    }

    private
    function setalerts($object, $objectid, $operation, $objectdata, $mandateid = '') {
      $insert = false;
      $stamp = time();
      $data = array();
      $data['createdat']  = $stamp;
      $data['modifiedat'] = $stamp;
      $data['creator']    = $this->userid;
      //$data['operation']  = $operation;
      $data['object']     = $object;
      $data['objectid']   = $objectid;
      if ($operation == 'CREATE') {
        if ($object == 'mandates') {
          $data['title']        = 'New mandate';
          $data['description']  = (isset($objectdata['name'])) ? $objectdata['name'] : '';
          $data['access']       = 'L2';
          $insert = true;
        }
        if (($object == 'users') && (isset($objectdata['type']))) {
          $type = $objectdata['type'];
          $data['title']        = 'New User';
          $data['description']  = (isset($objectdata['username'])) ? $objectdata['username'] : $object;

          if (($type == 'CUSTOMER')) {
            $data['access'] = 'L2';
          }
          else {
            $data['access'] = 'MASTERADMIN';
          }
          $insert = true;
        }
      }
      else if ($operation == 'UPDATE') {
        $olddata = $this->dbquery(sprintf("select * from %s where id=%s", $object, $objectid));
        if ((isset($olddata)) && (is_array($olddata)) && (count($olddata) > 0)) {
          $name = $object;
          if (isset($objectdata['name'])) {
            $name = $objectdata['name'];
          }
          else if (isset($olddata[0]['name'])) {
            $name = $olddata[0]['name'];
          }
          if ($object == 'mandates') {
            if (isset($objectdata['status'])) {
              $status = $objectdata['status'];
              if ($status == 'APPROVED') {
                $data['title']        = 'New mandate';
                $data['description']  = $name;
                $data['access']       = 'CUSTOMER';
                $insert = true;
              }
              else if ($status == 'PENDING') {
                $data['title']        = 'Mandate value changed';
                $data['description']  = $name;
                $data['access']       = 'L2';
                $insert = true;
              }
            }
          }
        }
      }
      if ($insert) {
        $res = $this->createentry('alerts', $data);
      }
    }

    private
    function setlogs($object, $objectid, $operation, $data) {
      if (($object == 'logs') || ($object == 'alerts')) {
        return 'failure';
      }
      $dataarray = $data;
      if (isset($this->userid)) {
        if (is_array($data)) {
          $ignore = array('createdat', 'modifiedat', 'creator', 'password', 'mandateid');
          foreach ($ignore as $ind => $val) {
            if (isset($data[$val])) {
               unset($data[$val]);
            }
          }
          $data = json_encode($data);
        }
        $mandateid = '';
        if (isset($_POST['mandateid'])) {
          $mandateid = $_POST['mandateid'];
        }
        if (isset($this->mandateid)) {
          $mandateid = $this->mandateid;
        }
        $stamp = time();
        $logdata = array();
        $logdata['createdat']  = $stamp;
        $logdata['modifiedat'] = $stamp;
        $logdata['creator']    = $this->userid;
        $logdata['mandateid']  = $mandateid;
        $logdata['operation']  = $operation;
        $logdata['object']     = $object;
        $logdata['objectid']   = $objectid;
        $logdata['data']       = $data;
        $res = $this->createentry('logs', $logdata);
        if ($res != false) {
          $this->setalerts($object, $objectid, $operation, $dataarray, $mandateid);
        }
      }
    }

    private
    function loaddashboard() {
      $stamp = time();

//Master admin : ongoing mandates, submitted mandates, pending requests
//Admin L1 and L2 : ongoing mandates, your mandates, pending customer requests 
//Customer : ongoing mandates, submitted nandates , completed mandates, allocated mandates

      $data = array();
      if ($this->usertype == 'masteradmin') {
        $query       = sprintf("select count(id) as count from users where type='ADMIN' and status='PENDING'");
        $pendinguser = $this->dbquery($query);
        if ((isset($pendinguser)) && (is_array($pendinguser)) && (count($pendinguser) > 0)) {
          $data['pendinguser'] = $pendinguser[0]['count'];
        }
      }
      else if ($this->usertype == 'customer') {
        $completedquery = sprintf("select count(id) as count from mandates where status='COMPLETED'");
        $completedquery = sprintf("select count(id) as count from mandates where access like '%%-%s-%%' and enddate < %s",$this->userid, $stamp);
        $completed      = $this->dbquery($completedquery);
        if ((isset($completed)) && (is_array($completed)) && (count($completed) > 0)) {
          $data['completed'] = $completed[0]['count'];
        }

        $allotedquery = sprintf("select count(id) as count from mandates where status='ALLOTED' and access like '%%-%s-%%'", $this->userid);
        $alloted      = $this->dbquery($allotedquery);
        if ((isset($alloted)) && (is_array($alloted)) && (count($alloted) > 0)) {
          $data['alloted'] = $alloted[0]['count'];
        }
      }
      $ongoingquery = sprintf("select count(id) as count from mandates where status='APPROVED' and startdate < %s and enddate > %s", $stamp, $stamp);
      $ongoing    = $this->dbquery($ongoingquery);
      if ((isset($ongoing)) && (is_array($ongoing)) && (count($ongoing) > 0)) {
        $data['ongoing'] = $ongoing[0]['count'];
      }

      if (($this->usertype == 'masteradmin') || ($this->usertype == 'customer')) {
        $submittedquery = sprintf("select count(id) as count from mandates where access like '%%-%s-%%'", $this->userid);
        if ($this->usertype == 'masteradmin') {
          $submittedquery = sprintf("select count(id) as count from mandates where access is not null");
        }
        $submitted      = $this->dbquery($submittedquery);
        if ((isset($submitted)) && (is_array($submitted)) && (count($submitted) > 0)) {
          $data['submitted'] = $submitted[0]['count'];
        }
      }

      if (($this->usertype == 'admin')) {
        $yourquery = sprintf("select count(id) as count from mandates where creator = %s", $this->userid);
        $your = $this->dbquery($yourquery);
        if ((isset($your)) && (is_array($your)) && (count($your) > 0)) {
          $data['yourmandate'] = $your[0]['count'];
        }

        $query       = sprintf("select count(id) as count from users where type='CUSTOMER' and status='PENDING'");
        $pendinguser = $this->dbquery($query);
        if ((isset($pendinguser)) && (is_array($pendinguser)) && (count($pendinguser) > 0)) {
          $data['pendingcustomer'] = $pendinguser[0]['count'];
        }
      }

      $this->response['status'] = 'success';
      $this->response['data']   = $data;
    }

    private
    function loadhistory() {
      if ((isset($_POST['object'])) && (isset($_POST['objectid']))) {
        $object   = $_POST['object'];
        $objectid = $_POST['objectid'];
        if ($this->usertype == 'customer') {
          if (isset($_POST['bidhistory']) && ($_POST['bidhistory'] == 'true')) {
            $query = sprintf("select * from logs where object='bids' and mandateid=%s and creator = %s order by id desc", $objectid, $this->userid);
          }
          else
            $query = sprintf("select * from logs where object='%s' and objectid=%s and creator=%s order by id desc", $object, $objectid, $this->userid);
        }
        else {
          if ($object == 'mandates') {
            if (isset($_POST['bidhistory']) && ($_POST['bidhistory'] == 'true')) {
              $query = sprintf("select * from logs where object='bids' and mandateid=%s and creator>0 order by id desc", $objectid);
            }
            else {
              $query = sprintf("select * from logs where object='%s' and objectid=%s order by id desc", $object, $objectid);
            }
          }
          else
            $query = sprintf("select * from logs where object='%s' and objectid=%s order by id desc", $object, $objectid);
        }
        if (isset($query)) {
          $res = $this->dbquery($query);
          if ((isset($res)) && (is_array($res)) && (count($res) > 0)) {
            $this->response['status'] = 'success';
            $this->response['data']   = $res;
          }
        }
      }
    }

    private
    function loadalerts() {
      $pointer   = (isset($_POST['pointer'])) ? $_POST['pointer'] : 0;
      $condition = '';
      $userstamp = (isset($this->userstamp)) ? $this->userstamp : 0;
      $query = sprintf("select * from alerts where (access = '%s' or access='%s' or userid=%s) and createdat > %s order by id desc", $this->usertype, $this->userlevel, $this->userid, $userstamp);
      $countquery = sprintf("select count(id) as count from alerts where (id > %s) and (createdat > %s) and (access = '%s' or access='%s' or userid=%s) order by id desc", $pointer, $userstamp, $this->usertype, $this->userlevel, $this->userid);
      $res = $this->dbquery($query);
      if ((isset($res)) && (is_array($res)) && (count($res) > 0)) {
        $count = $this->dbquery($countquery);
        if ((isset($count)) && (is_array($count)) && (count($count) > 0)) {
          $this->response['count']   = $count[0]['count'];
        }
        $this->response['status'] = 'success';
        $this->response['data']   = $res;
      }
    }

    private
    function allocate($mandate, $bids) {
      $stamp = time();
      $this->mandateid = $mandate['id'];
      $mandatekey      = $mandate['mandatekey'];
      usort($bids, function($a, $b) {
        if ($a['bidprice'] < $b['bidprice']) return 1;
        else if ($a['bidprice'] == $b['bidprice']) {
          if ($a['bidquantity'] < $b['bidquantity']) return 1;
          else return -1;
        }
        else return -1;
      });

      $floorprice        = $mandate['floorprice'];
      $pricetolerance    = $mandate['pricetolerance'];
      $priceticker       = $mandate['priceticker'];
      $floorquantity     = $mandate['floorquantity'];
      $quantitytolerance = $mandate['quantitytolerence'];
      $quantityticker    = $mandate['quantityticker'];
      $finalbids         = array();
      $rejectedbids      = array();
      for ($i = 0; $i < count($bids); $i++) {
        $bid = $bids[$i];
        $bidprice      = $bid['bidprice'];
        $bidquantity   = $bid['bidquantity'];
        if ($bidprice > $pricetolerance) {
          $rejected = $bid;
          $rejected['status']  = 'REJECTED';
          $rejected['message'] = 'Rejected due to price tolerance';
          $rejectedbids[]      = $rejected;
          //$this->debug($bidprice, 'Rejected due to price tolerance');
          continue;
        }
        else if ($bidprice < $floorprice) {
          $rejected = $bid;
          $rejected['status']  = 'REJECTED';
          $rejected['message'] = 'Rejected due to floor price';
          $rejectedbids[]      = $rejected;
          //$this->debug($bidprice, 'Rejected due to floor price');
          continue;
        }
        else if ($bidquantity > $quantitytolerance) {
          $rejected = $bid;
          $rejected['status']  = 'REJECTED';
          $rejected['message'] = 'Rejected due to quantity tolerance';
          $rejectedbids[]      = $rejected;
          //$this->debug($bidquantity, 'Rejected due to quantity tolerance');
          continue;
        }
        else if ($bidquantity < $floorquantity) {
          $rejected = $bid;
          $rejected['status']  = 'REJECTED';
          $rejected['message'] = 'Rejected due to floor quantity';
          $rejectedbids[]      = $rejected;
          //$this->debug($bidquantity, 'Rejected due to floor quantity');
          continue;
        }
        else {
          $afterqunatity = $bidquantity - $floorquantity;
          $afterprice = $bidprice - $floorprice;
          if (($afterqunatity > 0) && ($afterqunatity % $quantityticker != 0)) {
          $rejected = $bid;
          $rejected['status']  = 'REJECTED';
          $rejected['message'] = 'Rejected due to quantity ticker';
          $rejectedbids[]      = $rejected;
          //$this->debug($bidquantity, 'Rejected due to quantity ticker');
            continue;
          }
          else if (($afterprice > 0) && ($afterprice % $priceticker != 0)) {
          $rejected = $bid;
          $rejected['status']  = 'REJECTED';
          $rejected['message'] = 'Rejected due to price ticker';
          $rejectedbids[]      = $rejected;
          //$this->debug($bidprice, 'Rejected due to price ticker');
            continue;
          }
          else if (!isset($finalbids[$bidprice])) {
            $finalbids[$bidprice] = array();
            $finalbids[$bidprice]['totalbid'] = 0;
            $finalbids[$bidprice]['bids']     = array();
          }
          $finalbids[$bidprice]['totalbid'] += $bidquantity;
          $finalbids[$bidprice]['bids'][] = $bid;
        }
      }
      $mandatequantity = $mandate['totalquantity'];
      $totalquantity = $mandate['totalquantity'];
      $alloteddata = array();
      foreach ($finalbids as $price => $biddata) {
        $userbid = $biddata['bids'];
        if (count($userbid) == 1) {
          if ($totalquantity >= $floorquantity) {
            $userbid     = $userbid[0];
            $bidprice    = $userbid['bidprice'];
            $bidquantity = $userbid['bidquantity'];
            if ($bidquantity > $totalquantity) {
              $bidquantity = $totalquantity;
            }
            if ($totalquantity >= $bidquantity) {
              $userbid['alloted'] = $bidquantity;
              $alloteddata[] = $userbid;
              $totalquantity = $totalquantity - $bidquantity;
            }
          }
        }
        else {
          $totalbid          = $biddata['totalbid'];
          $remainingquantity = $totalquantity;
          foreach($userbid as $ind => $bidinfo) {
            if ($totalquantity >= $floorquantity) {
              $bidprice    = $bidinfo['bidprice'];
              $bidquantity = $bidinfo['bidquantity'];
              $ratio = ($bidquantity * 100) / $totalbid;
              $bidratio = ($ratio * $remainingquantity) / 100;
              if ($bidratio > $bidquantity) {
                $bidratio = $bidquantity;
              }
              if (fmod($bidratio, $quantityticker) > 0) {
                $remainder = ceil($bidratio / $quantityticker);
                $bidratio = $remainder * $quantityticker;
              }
              if ($bidratio > $totalquantity) {
                $bidratio = $totalquantity;
              }
              if (($bidratio < $floorquantity) && ($floorquantity <= $bidquantity)) {
                $bidratio = $floorquantity;
              }
              if (($bidratio <= $totalquantity) && ($bidratio >= $floorquantity)) {
                $userbid = $bidinfo;
                $userbid['alloted'] = $bidratio;
                $alloteddata[] = $userbid;
                $totalquantity = $totalquantity - $bidratio;
              }
            }
          }
        }
      }
      if (count($alloteddata) > 0) {
        foreach ($alloteddata as $ind => $val) {
          $bidqunatity     = $val['bidquantity'];
          $allotedqunatity = $val['alloted'];
          if (($totalquantity > 0) && ($allotedqunatity < $bidqunatity)) {
            $alloted = $allotedqunatity + $totalquantity;
            if (fmod($alloted, $quantityticker) != 0) {
              $remainder = floor($alloted / $quantityticker);
              $alloted   = $remainder * $quantityticker;
            }
            if (($alloted <= $bidqunatity)) {
              $val['alloted'] = $alloted;
              $alloteddata[$ind] = $val;
            }
          }
        }
      }

      foreach ($bids as $biddata) {
        $notalloted = true;
        $bidid = $biddata['id'];
        if ((isset($rejectedbids)) && (is_array($rejectedbids)) && (count($rejectedbids) > 0)) {
          foreach ($rejectedbids as $rejected) {
            $rejetedid = $rejected['id'];
            if ($bidid == $rejetedid) {
              $notalloted = false;
              break;
            }
          }
        }
        if (($notalloted) && (isset($alloteddata)) && (is_array($alloteddata)) && (count($alloteddata) > 0)) {
          foreach ($alloteddata as $allotedbid) {
            if ((isset($allotedbid['id'])) && (isset($allotedbid['status'])) && (isset($allotedbid['alloted']))) {
              $allotedid = $allotedbid['id'];
              if ($bidid == $allotedid) {
                $notalloted = false;
                break;
              }
            }
          }
        }
        if ($notalloted) {
          $rejecteddata = array();
          $rejecteddata['mandatekey'] = $mandatekey;
          $rejecteddata['status']     = 'NOTALLOTED';
          $res = $this->updateentry('bids', $rejecteddata, sprintf("id=%s and status = 'NEW'", $bidid), $bidid);
        }
      }

        if ((isset($rejectedbids)) && (is_array($rejectedbids)) && (count($rejectedbids) > 0)) {
          foreach ($rejectedbids as $rejected) {
            if ((isset($rejected['id'])) && (isset($rejected['status'])) && (isset($rejected['message']))) {
              $rejetedid = $rejected['id'];
              $rejecteddata = array();
              $rejecteddata['mandatekey'] = $mandatekey;
              $rejecteddata['status']     = $rejected['status'];
              $rejecteddata['message']    = $rejected['message'];
              $res = $this->updateentry('bids', $rejecteddata, sprintf("id=%s and status = 'NEW'", $rejetedid), $rejetedid);
              if ($res != false) {
                $alertdata = array();
                $alertdata['createdat']    = $stamp;
                $alertdata['modifiedat']   = $stamp;
                $alertdata['creator']      = $this->userid;
                $alertdata['object']       = 'mandates';
                $alertdata['objectid']     = $mandate['id'];
                $alertdata['title']        = 'Bid rejected';
                $alertdata['description']  = $mandate['name'];
                $alertdata['userid']       = $rejected['creator'];
                $res = $this->createentry('alerts', $alertdata);
              }
            }
          }
        }
      if ($mandatequantity == $totalquantity) {
        $mandatedata = array();
        $mandatedata['status'] = 'ERROR';
        $res = $this->updateentry('mandates', $mandatedata, sprintf("id=%s and status = 'APPROVED'", $mandate['id']), $mandate['id']);
        $alertdata = array();
        $alertdata['createdat']    = $stamp;
        $alertdata['modifiedat']   = $stamp;
        $alertdata['creator']      = $this->userid;
        $alertdata['object']       = 'mandates';
        $alertdata['objectid']     = $mandate['id'];
        $alertdata['title']        = 'Allocation error in mandate';
        $alertdata['description']  = $mandate['name'];
        $alertdata['userid']       = $mandate['creator'];
        $res = $this->createentry('alerts', $alertdata);
      }
      else if ($totalquantity < $mandatequantity) {
        if ((isset($rejectedbids)) && (is_array($rejectedbids)) && (count($rejectedbids) > 0)) {
          foreach ($rejectedbids as $rejected) {
            if ((isset($rejected['id'])) && (isset($rejected['status'])) && (isset($rejected['message']))) {
              $rejetedid = $rejected['id'];
              $rejecteddata = array();
              $rejecteddata['mandatekey'] = $mandatekey;
              $rejecteddata['status']     = $rejected['status'];
              $rejecteddata['message']    = $rejected['message'];
              $res = $this->updateentry('bids', $rejecteddata, sprintf("id=%s and status = 'NEW'", $rejetedid), $rejetedid);
              if ($res != false) {
                $alertdata = array();
                $alertdata['createdat']    = $stamp;
                $alertdata['modifiedat']   = $stamp;
                $alertdata['creator']      = $this->userid;
                $alertdata['object']       = 'mandates';
                $alertdata['objectid']     = $mandate['id'];
                $alertdata['title']        = 'Bid rejected';
                $alertdata['description']  = $mandate['name'];
                $alertdata['userid']       = $rejected['creator'];
                $res = $this->createentry('alerts', $alertdata);
              }
            }
          }
        }
        if ((isset($alloteddata)) && (is_array($alloteddata)) && (count($alloteddata) > 0)) {
          foreach ($alloteddata as $allotedbid) {
            if ((isset($allotedbid['id'])) && (isset($allotedbid['status'])) && (isset($allotedbid['alloted']))) {
              $allotedid = $allotedbid['id'];
              $alloteddata = array();
              $alloteddata['mandatekey'] = $mandatekey;
              $alloteddata['status']     = 'ALLOTED';
              $alloteddata['alloted']    = $allotedbid['alloted'];
              $res = $this->updateentry('bids', $alloteddata, sprintf("id=%s and status = 'NEW'", $allotedid), $allotedid);
              if ($res != false) {
                $alertdata = array();
                $alertdata['createdat']    = $stamp;
                $alertdata['modifiedat']   = $stamp;
                $alertdata['creator']      = $this->userid;
                $alertdata['object']       = 'mandates';
                $alertdata['objectid']     = $mandate['id'];
                $alertdata['title']        = 'Mandate allocation is done';
                $alertdata['description']  = $mandate['name'];
                $alertdata['userid']       = $allotedbid['creator'];
                $res = $this->createentry('alerts', $alertdata);
              }
            }
          }
        }
        $mandatedata = array();
        $mandatedata['status'] = 'ALLOTED';
        $res = $this->updateentry('mandates', $mandatedata, sprintf("id=%s and status = 'APPROVED'", $mandate['id']), $mandate['id']);
        $alertdata = array();
        $alertdata['createdat']    = $stamp;
        $alertdata['modifiedat']   = $stamp;
        $alertdata['creator']      = $this->userid;
        $alertdata['object']       = 'mandates';
        $alertdata['objectid']     = $mandate['id'];
        $alertdata['title']        = 'Mandate allocation is done';
        $alertdata['description']  = $mandate['name'];
        $alertdata['userid']       = $mandate['creator'];
        $res = $this->createentry('alerts', $alertdata);
      }
    }

    private
    function autoallocate() {
      $this->userid = 0;
      $stamp = time();
      $query = sprintf("select * from mandates where status='APPROVED' and enddate<%s", $stamp);
      $mandates = $this->dbquery($query);
      if ((isset($mandates)) && (is_array($mandates)) && (count($mandates) > 0)) {
        foreach ($mandates as $mandate) {
          $query = sprintf("select * from bids where mandateid=%s and status='NEW'", $mandate['id']);
          $bids  = $this->dbquery($query);
          if ((isset($bids)) && (is_array($bids)) && (count($bids) > 0)) {
            $this->allocate($mandate, $bids);
            $access = '';
            foreach ($bids as $bid) {
              if (isset($bid['creator'])) {
                $access = sprintf('%s-%s-', $access, $bid['creator']);
              }
            }
            $updatequery = sprintf("update mandates set access='%s' where id=%s", $access, $mandate['id']);
            $this->dbquery($updatequery);
          }
          else if ((isset($bids)) && (is_array($bids)) && (count($bids) == 0)) {
            $updatequery = sprintf("update mandates set status='COMPLETED' where id=%s and status='APPROVED'", $mandate['id']);
            $this->dbquery($updatequery);
          }
        }
      }
    }

    private
    function setaccess($mandateid) {
      $query = sprintf("select * from bids where mandateid=%s", $mandateid);
      $bids  = $this->dbquery($query);
      if ((isset($bids)) && (is_array($bids)) && (count($bids) > 0)) {
        $access = '';
        foreach ($bids as $bid) {
          if (isset($bid['creator'])) {
            $access = sprintf('%s-%s-', $access, $bid['creator']);
          }
        }
      }
      $updatequery = sprintf("update mandates set access='%s' where id=%s", $access, $mandateid);
      $this->dbquery($updatequery);
    }

    private
    function forgotpassword() {
      if (isset($_POST['email'])) {
        $users = $this->dbquery(sprintf("select * from users where email='%s'", $_POST['email']));
        if ((isset($users)) && (is_array($users)) && (count($users) > 0)) {
          $status = $users[0]['status'];
          $this->response['status']     = 'success';
          $this->response['userstatus'] = $status;
          if (($status == 'PENDING') || ($status == 'APPROVED')) {
          }
          else {
            $this->response['error'] = 'This account is not active, please contact XXXX@bharatpetroleum.in';
          }
        }
      }
    }

    private
    function fieldvisibility() {
      if ((isset($_POST['object'])) && (isset($_POST['objectid'])) && (isset($_POST['field'])) && (isset($_POST['visible']))) {
        $object   = $_POST['object'];
        $objectid = $_POST['objectid'];
        $field    = $_POST['field'];
        $visible  = $_POST['visible'];

        $query = sprintf("select * from %s where creator=%s", $object, $this->userid);
        $objectinfo = $this->dbquery($query);
        if ((isset($objectinfo)) && (is_array($objectinfo)) && (count($objectinfo) > 0)) {
          $query = sprintf("select * from hidefields where object='%s' and objectid=%s", $object, $objectid);
          $res = $this->dbquery($query);
          if ((isset($res)) && (is_array($res)) && (count($res) >= 0)) {
            $stamp = time();
            if (count($res) == 0) {
              if ($visible == 'false') {
                $newdata = array();
                $newdata['createdat']    = $stamp;
                $newdata['modifiedat']   = $stamp;
                $newdata['creator']      = $this->userid;
                $newdata['object']       = $object;
                $newdata['objectid']     = $objectid;
                $newdata['fields']       = json_encode(array($field));
                $res = $this->createentry('hidefields', $newdata);
                if ($res != false) {
                  $this->response['status'] = 'success';
                }
              }
            }
            else if ((isset($res[0]['fields'])) && ($this->isjson($res[0]['fields']))) {
              $fields = json_decode($res[0]['fields'], true);
              if ((isset($fields))) {
                if (($visible == 'true') && (in_array($field, $fields))) {
                  $key = array_search($field, $fields);
                  if ($key !== false) {
                    unset($fields[$key]);
                    $fields = array_values($fields);
                  }
                }
                else if (($visible == 'false') && (!in_array($field, $fields))) {
                  array_push($fields, $field);
                }
                $res = $this->updateentry('hidefields', array('fields' => json_encode($fields)), sprintf("id=%s", $res[0]['id']), $res[0]['id']);
              }
            }
          }
        }
      }
    }

    public
    function run($action = null) {
      if ((isset($action)) && ($action != null)) {
        $this->action = $action;
      }
      if ($this->dbinit()) {
        if ($this->action == 'ALLOCATE')
          return $this->autoallocate();
        else if ($this->action == 'LOADPAGE')
          return $this->loadpage();
        else if ($this->action == 'REGISTER')
          $this->register();
        else if ($this->action == 'MEDIAUPLOAD')
          $this->mediaupload();
        else if ($this->action == 'FORGOTPASSWORD')
          $this->forgotpassword();
        else if ($this->authenticate()) {
          if ($this->action == 'CREATE')               $this->create();
          else if ($this->action == 'UPDATE')          $this->update();
          else if ($this->action == 'LOADDATA')        $this->loaddata();
          else if ($this->action == 'LOADLIST')        $this->loadlist();
          else if ($this->action == 'MANDATEACTION')   $this->mandateaction();
          else if ($this->action == 'DOWNLOADREPORT')  $this->downloadreport();
          else if ($this->action == 'LOADDASHBOARD')   $this->loaddashboard();
          else if ($this->action == 'LOADHISTORY')     $this->loadhistory();
          else if ($this->action == 'LOADALERTS')      $this->loadalerts();
          else if ($this->action == 'RESETPASSWORD')   $this->resetpassword();
          else if ($this->action == 'FIELDVISIBILITY') $this->fieldvisibility();
          else if ($this->action == 'VIEW')            $this->view();
        }
        else
          return $this->loadpage();

        if ($this->action != 'LOADPAGE')
          return $this->respond();
      }
    }
  }
?>
