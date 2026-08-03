<?php

function patch_attr(string $attr, string $pathVal): string
{
    ob_start();
    echo $attr, '="';
    echo "'";
    echo ' . hpath(\'';
    echo $pathVal;
    echo '\') . ';
    echo "'";
    echo ' . \\\'"';
    return ob_get_clean();
}

echo patch_attr('action', '/logout') . "\n";
