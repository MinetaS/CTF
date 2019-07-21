<!DOCTYPE html>
<html>
<head>
<title>PHP Practice</title>
</head>
<body>

<a href="?page=p.php">p tag</a>
<a href="?page=h1.php">h1 tag</a>

<?php
if (isset($_GET['page'])) {
  if ($_GET['page'] === 'admin') {
    echo "<script>location.href='admin.php?pw=" . $_GET['pw'] . "'</script>";
  }
  else {
    include($_GET['page']);
  }
}
else {
  ?>
This is a default page.
  <?php
}
?>

</body>
</html>
