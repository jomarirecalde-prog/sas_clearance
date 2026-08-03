<?php

declare(strict_types=1);

namespace App\Support;

/**
 * JPEG embedded by Dompdf does not require GD; PNG/WebP/GIF do. Normalize for PDF output.
 */
final class SignatureImage
{
    public static function rasterBinaryToJpeg(string $binary, int $quality = 90): ?string
    {
        $info = @getimagesizefromstring($binary);
        if ($info === false) {
            return null;
        }
        $mime = (string) ($info['mime'] ?? '');
        if ($mime === 'image/jpeg') {
            return $binary;
        }

        if (extension_loaded('gd') && function_exists('imagecreatefromstring') && function_exists('imagejpeg')) {
            $im = @imagecreatefromstring($binary);
            if ($im !== false) {
                $w = imagesx($im);
                $h = imagesy($im);
                if ($w > 0 && $h > 0) {
                    $canvas = imagecreatetruecolor($w, $h);
                    if ($canvas !== false) {
                        $white = imagecolorallocate($canvas, 255, 255, 255);
                        imagefill($canvas, 0, 0, $white);
                        imagealphablending($canvas, true);
                        imagecopy($canvas, $im, 0, 0, 0, 0, $w, $h);
                        ob_start();
                        imagejpeg($canvas, null, $quality);
                        $out = ob_get_clean();
                        imagedestroy($canvas);
                        imagedestroy($im);
                        if ($out !== false && $out !== '') {
                            return $out;
                        }
                    } else {
                        imagedestroy($im);
                    }
                } else {
                    imagedestroy($im);
                }
            }
        }

        if (extension_loaded('imagick')) {
            try {
                $img = new \Imagick();
                $img->readImageBlob($binary);
                $img->setImageBackgroundColor(new \ImagickPixel('white'));
                $img->setImageAlphaChannel(\Imagick::ALPHACHANNEL_REMOVE);
                $img = $img->mergeImageLayers(\Imagick::LAYERMETHOD_FLATTEN);
                $img->setImageFormat('jpeg');
                $img->setImageCompressionQuality($quality);
                $blob = $img->getImageBlob();
                $img->clear();
                $img->destroy();
                if ($blob !== '') {
                    return $blob;
                }
            } catch (\Throwable) {
            }
        }

        return null;
    }

    public static function filePathToDompdfDataUri(string $absolutePath): ?string
    {
        if (!is_file($absolutePath)) {
            return null;
        }
        $binary = @file_get_contents($absolutePath);
        if ($binary === false || $binary === '') {
            return null;
        }
        $mime = mime_content_type($absolutePath) ?: '';
        if ($mime === 'image/jpeg' || $mime === 'image/jpg') {
            return 'data:image/jpeg;base64,' . base64_encode($binary);
        }
        $jpeg = self::rasterBinaryToJpeg($binary);
        if ($jpeg !== null) {
            return 'data:image/jpeg;base64,' . base64_encode($jpeg);
        }

        return null;
    }
}
