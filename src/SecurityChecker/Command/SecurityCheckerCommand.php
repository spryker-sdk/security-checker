<?php
declare(strict_types = 1);

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SecurityChecker\Command;

use SecurityChecker\Result;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Exception\RuntimeException;
use Symfony\Component\Process\Process;

class SecurityCheckerCommand extends Command
{
    protected const CODE_SUCCESS = 0;
    protected const CODE_ERROR = 1;

    protected const COMMAND_NAME = 'security:check';

    protected const BINARY_CHECKER = '$(curl -s https://api.github.com/repos/fabpot/local-php-security-checker/releases/latest | grep browser_download_url | cut -d\" -f4 | egrep "local-php-security-checker_[0-9.]+_linux_amd64$")';
    protected const FILE_NAME = '/tmp/security-checker';
    protected const FALSE_POSITIVE_ISSUE_NUMBER = 'CVE-NONE-0001';

    protected const OPTION_FORMAT = 'format';
    protected const OPTION_PATH = 'path';

    /**
     * @return void
     */
    protected function configure(): void
    {
        $this
            ->setName(static::COMMAND_NAME)
            ->setDescription('Checks security issues in your project dependencies')
            ->addOption(
                static::OPTION_FORMAT,
                'f',
                InputOption::VALUE_OPTIONAL,
                'Set format for checker',
            )
            ->addOption(
                static::OPTION_PATH,
                'p',
                InputOption::VALUE_OPTIONAL,
                'Set path for checker',
            );
    }

    /**
     * @param \Symfony\Component\Console\Input\InputInterface $input
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int
     */
    public function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->loadFile();
        $parameters = $this->getParameters($input);
        $commandOutput = $this->runCommand($parameters);
        $commandOutput = $this->markFalsePositiveResults($commandOutput);

        $result = $this->createResultFromCommandOutput($commandOutput);

        $output->writeln($result->getVulnerabilities());

        return $this->convertResultToExitCode($result, $output);
    }

    /**
     * @param \Symfony\Component\Console\Input\InputInterface $input
     *
     * @return string[]
     */
    protected function getParameters(InputInterface $input): array
    {
        $parameters = [];

        if ($input->getOption(static::OPTION_PATH)) {
            $parameters[] = sprintf('--%s=%s', static::OPTION_PATH, $input->getOption(static::OPTION_PATH));
        }

        if ($input->getOption(static::OPTION_FORMAT)) {
            $parameters[] = sprintf('--%s=%s', static::OPTION_FORMAT, $input->getOption(static::OPTION_FORMAT));
        }

        return $parameters;
    }

    /**
     * @throws \Symfony\Component\Process\Exception\RuntimeException
     *
     * @return void
     */
    protected function loadFile(): void
    {
        if (file_exists(static::FILE_NAME)) {
            return;
        }

        exec(sprintf('wget %s -O %s 2>&1', static::BINARY_CHECKER, static::FILE_NAME), $output, $resultCode);

        if ($resultCode === static::CODE_ERROR) {
            throw new RuntimeException(implode(PHP_EOL, $output));
        }

        $this->changeFileMode();
    }

    /**
     * @return void
     */
    protected function changeFileMode(): void
    {
        chmod(static::FILE_NAME, 0777);
    }

    /**
     * @param string[] $parameters
     *
     * @throws \Symfony\Component\Process\Exception\ProcessFailedException
     *
     * @return string
     */
    protected function runCommand(array $parameters): string
    {
        $parameters = array_merge([static::FILE_NAME], $parameters);

        $process = new Process($parameters);
        $process->run();

        if (!empty($process->getErrorOutput())) {
            throw new ProcessFailedException($process);
        }

        return $process->getOutput();
    }

    /**
     * @param string $commandOutput
     *
     * @return \SecurityChecker\Result
     */
    protected function createResultFromCommandOutput(string $commandOutput): Result
    {
        $count = 0;
        preg_match('/\d\spackage/m', $commandOutput, $matches);
        if (!empty($matches)) {
            $count = (int)$matches[0];
        }

        return new Result($count, $commandOutput);
    }

    /**
     * @param string $commandOutput
     *
     * @return string
     */
    protected function markFalsePositiveResults(string $commandOutput): string
    {
        if (strpos($commandOutput, static::FALSE_POSITIVE_ISSUE_NUMBER) !== false) {
            $commandOutput = str_replace(
                static::FALSE_POSITIVE_ISSUE_NUMBER,
                sprintf('<info>%s - is a false positive</info>', static::FALSE_POSITIVE_ISSUE_NUMBER),
                $commandOutput
            );
        }

        return $commandOutput;
    }

    /**
     * @param \SecurityChecker\Result $result
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int
     */
    protected function convertResultToExitCode(Result $result, OutputInterface $output): int
    {
        if ($result->count() === 0) {
            return static::CODE_SUCCESS;
        }

        if (!$this->checkResultForFalsePositiveCase($result)) {
            return static::CODE_ERROR;
        }

        if ($output->isVerbose()) {
            $output->writeln(sprintf('<info>The issue about %s is a false positive result</info>', static::FALSE_POSITIVE_ISSUE_NUMBER));
            $output->writeln('<info>Check https://github.com/FriendsOfPHP/security-advisories/issues/511 for details</info>');
        }

        return static::CODE_SUCCESS;
    }

    /**
     * @param \SecurityChecker\Result $result
     *
     * @return bool
     */
    protected function checkResultForFalsePositiveCase(Result $result): bool
    {
        return $result->count() === 1 && strpos($result->getVulnerabilities(), static::FALSE_POSITIVE_ISSUE_NUMBER) !== false;
    }
}
