<?php

use Hcode\Model\Product;
use \Hcode\Page;

$app->get('/', function() {

$products = Product::listAll();

$page = new Page();

$page->setTpl("index", [
    'products'=>Product::checkList($products)
]);

});