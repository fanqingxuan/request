<?php

namespace Json\Request;

/**
 * Json\Request\File
 *
 * Provides OO wrappers to the $_FILES superglobal
 *
 *```php
 * use Json\Request;
 *
 * class PostsController extends Controller
 * {
 *     public function uploadAction()
 *     {
 *         // Check if the user has uploaded files
 *         if ($this->request->hasFiles() == true) {
 *             // Print the real file names and their sizes
 *             foreach ($this->request->getUploadedFiles() as $file) {
 *                 echo $file->getName(), " ", $file->getSize(), "\n";
 *             }
 *         }
 *     }
 * }
 *```
 */
class File implements FileInterface
{
    /**
     * @var string|null
     */
    protected $error;
    
    public function getError() {
        return $this->error;
    }

    /**
     * @var string
     */
    protected $extension;
    
    public function getExtension() {
        return $this->extension;
    }

    /**
     * @var string|null
     */
    protected $key;
    
    public function getKey() {
        return $this->key;
    }

    protected $name;

    protected $realType;

    protected $size;

    protected $tmp;

    protected $type;

    /**
     * Json\Request\File constructor
     */
    public function __construct($file, $key = null)
    {
        if (isset($file["name"])) {
            $name = $file["name"];
            $this->name = $name;

            if (defined("PATHINFO_EXTENSION")) {
                $this->extension = pathinfo($name, PATHINFO_EXTENSION);
            }
        }

        if (isset($file["tmp_name"])) {
            $this->tmp = $file["tmp_name"];
        }

        if (isset($file["size"])) {
            $this->size = $file["size"];
        }

        if (isset($file["type"])) {
            $this->type = $file["type"];
        }

        if (isset($file["error"])) {
            $this->error = $file["error"];
        }

        if ($key) {
            $this->key = $key;
        }
    }

    /**
     * Returns the real name of the uploaded file
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Gets the real mime type of the upload file using finfo
     */
    public function getRealType()
    {

        $finfo = finfo_open(FILEINFO_MIME_TYPE);

        if (gettype($finfo) != "resource") {
            return "";
        }

        $mime = finfo_file($finfo, $this->tmp);

        finfo_close($finfo);

        return $mime;
    }

    /**
     * Returns the file size of the uploaded file
     */
    public function getSize()
    {
        return $this->size;
    }

    /**
     * Returns the temporary name of the uploaded file
     */
    public function getTempName()
    {
        return $this->tmp;
    }

    /**
     * Returns the mime type reported by the browser
     * This mime type is not completely secure, use getRealType() instead
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Checks whether the file has been uploaded via Post.
     */
    public function isUploadedFile()
    {
        $tmp = $this->getTempName();

        return gettype($tmp) == "string" && is_uploaded_file($tmp);
    }

    /**
     * Moves the temporary file to a destination within the application
     */
    public function moveTo($destination)
    {
        return move_uploaded_file($this->tmp, $destination);
    }
}
