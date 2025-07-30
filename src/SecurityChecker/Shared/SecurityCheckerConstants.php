<?php

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SecurityChecker\Shared;

/**
 * Declares global environment configuration keys. Do not use it for other class constants.
 */
interface SecurityCheckerConstants
{
    /**
     * @var string
     */
    public const FILESYSTEM_NAME = 's3-import';

    /**
     * @var string
     */
    public const SECURITY_CHECKER_BINARY_FILENAME = 'security-checker-binary';
}
