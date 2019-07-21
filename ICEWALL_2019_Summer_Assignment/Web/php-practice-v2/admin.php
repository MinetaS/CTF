<?php
  if ($_GET['pw'] === 'p@ssw0rd') {
    system("echo 'Hello admin!'");
  }
  else {
    system("echo 'wrong password : ". $_GET['pw'] ."'");
  }
?>
