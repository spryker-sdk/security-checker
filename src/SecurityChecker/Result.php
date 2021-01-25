<?php
declare(strict_types = 1);

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SecurityChecker;

use Countable;

class Result implements Countable
{
    /**
     * @var int
     */
    protected $count;

    /**
     * @var string
     */
    protected $vulnerabilities;

    /**
     * @param int $count
     * @param string $vulnerabilities
     */
    public function __construct(int $count, string $vulnerabilities)
    {
        $this->count = $count;
        $this->vulnerabilities = $vulnerabilities;
    }

    /**
     * @return string
     */
    public function getVulnerabilities(): string
    {
        return $this->vulnerabilities;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->vulnerabilities;
    }

    /**
     * @return int
     */
    public function count(): int
    {
        return $this->count;
    }
}
