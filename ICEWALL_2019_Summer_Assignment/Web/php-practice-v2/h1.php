<h1>This is a h1 tag</h1>

<?php
if (isset($_GET['page2'])) {
  if ($_GET['page2'] === 'admin') {
    echo "<script>location.href='admin.php?pw=" . $_GET['pw'] . "'</script>";
  }
  else {
    include($_GET['page2']);
  }
}
?>
