<?php

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SecurityChecker\Dependency\Service;

use Generated\Shared\Transfer\FileSystemContentTransfer;
use Generated\Shared\Transfer\FileSystemDeleteTransfer;
use Generated\Shared\Transfer\FileSystemQueryTransfer;
use Generated\Shared\Transfer\FileSystemStreamTransfer;
use Spryker\Service\FileSystem\FileSystemServiceInterface;

class SecurityCheckerToFileSystemServiceBridge implements SecurityCheckerToFileSystemServiceInterface
{
    /**
     * @var \Spryker\Service\FileSystem\FileSystemServiceInterface
     */
    protected FileSystemServiceInterface $fileSystemService;

    /**
     * @param \Spryker\Service\FileSystem\FileSystemServiceInterface $fileSystemService
     */
    public function __construct(FileSystemServiceInterface $fileSystemService)
    {
        $this->fileSystemService = $fileSystemService;
    }

    /**
     * @param \Generated\Shared\Transfer\FileSystemContentTransfer $fileSystemContentTransfer
     *
     * @return void
     */
    public function write(FileSystemContentTransfer $fileSystemContentTransfer): void
    {
        $this->fileSystemService->write($fileSystemContentTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\FileSystemStreamTransfer $fileSystemStreamTransfer
     *
     * @return resource
     */
    public function readStream(FileSystemStreamTransfer $fileSystemStreamTransfer)
    {
        return $this->fileSystemService->readStream($fileSystemStreamTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\FileSystemQueryTransfer $fileSystemQueryTransfer
     *
     * @return string
     */
    public function read(FileSystemQueryTransfer $fileSystemQueryTransfer): string
    {
        return $this->fileSystemService->read($fileSystemQueryTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\FileSystemDeleteTransfer $fileSystemDeleteTransfer
     *
     * @return bool
     */
    public function delete(FileSystemDeleteTransfer $fileSystemDeleteTransfer): bool
    {
        $this->fileSystemService->delete($fileSystemDeleteTransfer);
        return true;
    }

    /**
     * @param \Generated\Shared\Transfer\FileSystemQueryTransfer $fileSystemQueryTransfer
     *
     * @return bool
     */
    public function has(FileSystemQueryTransfer $fileSystemQueryTransfer): bool
    {
        return $this->fileSystemService->has($fileSystemQueryTransfer) === true;
    }

    /**
     * @param \Generated\Shared\Transfer\FileSystemQueryTransfer $fileSystemQueryTransfer
     *
     * @return int|null
     */
    public function getTimestamp(FileSystemQueryTransfer $fileSystemQueryTransfer): ?int
    {
        return $this->fileSystemService->getTimestamp($fileSystemQueryTransfer);
    }
}
