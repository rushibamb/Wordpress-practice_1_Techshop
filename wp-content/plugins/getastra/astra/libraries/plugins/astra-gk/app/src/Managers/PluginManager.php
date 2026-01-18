<?php
/**
 * This file is part of the Astra Security Suite
 *
 *  Copyright (c) 2019 (https://www.getastra.com/)
 *
 *  For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
 *
 */

/**
 *
 *
 * @author HumansofAstra-WZ <help@getastra.com>
 * @date   2019-03-10
 */

namespace GetAstra\Managers;

use Interop\Container\ContainerInterface;
use GetAstra\Helpers\OptionsHelper as Options;
use Symfony\Component\Finder\Finder;

class PluginManager
{

    /**
     * @var \Interop\Container\ContainerInterface
     */
    private $container;

    /**
     * Settings for the Plugin Manager
     *
     * @var string
     */
    private $settings;

    /**
     * Path to the plugin directory, coming from Configuration class.
     *
     * @var string
     */
    private $pluginPath;

    /**
     * Keep loaded modules in cache.
     *
     * @var array
     */
    private $loadedModules;

    private $dispatcher;

    /**
     * Paths of route files for plugins
     *
     * @var array
     */
    private $routesFiles;

    /**
     * PluginManager constructor.
     *
     * @param \Interop\Container\ContainerInterface $container
     *
     */
    public function __construct(ContainerInterface $container = null)
    {
        $this->container = $container;
        $this->settings = $container->get('settings')['plugins'];

        $this->pluginPath = $this->settings['path'];
        $this->dispatcher = $this->container->get('dispatcher');
        $this->loadedModules = array();
        $this->routesFiles = array();
    }

    public function getRoutesFiles()
    {
        return $this->routesFiles;
    }

    /**
     * Instanciate every module present in the modules folder.
     *
     */
    private function getPluginsOnDisk()
    {
        //TODO Implement a method to retrieve all plugins in the plugins folder
        $plugins = array();

        $finder = new Finder();
        $finder->directories()->in($this->pluginPath)->depth(0);

        foreach ($finder as $pluginFolder) {
            $relFolderPath =  $pluginFolder->getRelativePathname();
            $pluginFileName = $relFolderPath . DIRECTORY_SEPARATOR . $relFolderPath . '.php';
            if(file_exists($this->pluginPath . $pluginFileName)){
                 $plugins[] = $pluginFileName;
            }
        }

        return $plugins;

    }

    public function activatePluginsOnDisk(){
        $plugins = $this->getPluginsOnDisk();
        $this->activatePlugins($plugins);
    }

    /**
     * Get all the Active plugins as stored in the database
     *
     */
    public function getActivePlugins()
    {
        $plugins = Options::get('active_plugins');

        if(empty($plugins)){
            $plugins = $this->getPluginsOnDisk();
            $this->activatePlugins($plugins);
        }

        return $plugins;

    }

    public function activatePlugin($plugin, $silent = false)
    {
        $current = Options::get('active_plugins');

        if (in_array($plugin, $current)) {
            return true;
        }

        $current[] = $plugin;
        Options::set('active_plugins', $current);

        if (!$silent) {

            /**
             * Fires before a plugin is activated.
             *
             * If a plugin is silently activated (such as during an update),
             * this hook does not fire.
             */

            $pluginName = $this->getPluginBaseName($plugin);
            $this->dispatcher->dispatch('plugin.' . $pluginName . '.activated');
        }

        return true;
    }

    public function deactivatePlugin($plugin, $silent = false)
    {

        $current = Options::get('active_plugins');

        if (!in_array($plugin, $current)) {
            return true;
        }

        if (false !== ($currentKey = array_search($plugin, $current))) {
            unset($current[$currentKey]);
        }

        Options::set('active_plugins', $current);

        if (!$silent) {
            $pluginName = $this->getPluginBaseName($plugin);
            $this->dispatcher->dispatch('plugin.' . $pluginName . '.deactivated');
        }

        return true;
    }

    public function activatePlugins($plugins = array(), $silent = false)
    {
        if (!is_array($plugins)) {
            $plugins = array($plugins);
        }

        foreach ($plugins as $plugin) {
            $this->activatePlugin($plugin, $silent);
        }

        return true;
    }

    public function deactivatePlugins($plugins = array(), $silent = false)
    {
        if (!is_array($plugins)) {
            $plugins = array($plugins);
        }

        foreach ($plugins as $plugin) {
            $this->deactivatePlugin($plugin, $silent);
        }

        return true;
    }

    public function runAllPlugins()
    {
        $plugins = $this->getActivePlugins();

        foreach ($plugins as $plugin) {
            $this->runPlugin($plugin);
            //$this->dispatcher->addSubscriber(new $className($container));
        }
    }

    public function runPlugin($plugin)
    {
        $filePath = $this->pluginPath . $plugin;
        $folderPath = $this->pluginPath . dirname($plugin);
        $pluginName = $this->getPluginBaseName($plugin);

        if (!file_exists($filePath)) {
            //TODO Dispatch the plugin.deactivated event
            return false;
        }


        include_once($filePath);

        $pluginClassName = 'GetAstra\\Plugins\\' . $pluginName;
        if (!class_exists($pluginClassName)) {
            $pluginClassName = 'GetAstra\\Plugins\\' . ucfirst($pluginName);
            if (!class_exists($pluginClassName)) {
                //TODO Dispatch the plugin.deactivated event
                return false;
            }
        }

        $routesPath = $folderPath . DIRECTORY_SEPARATOR . 'routes.php';

        if (file_exists($routesPath)) {
            $this->routesFiles[] = $routesPath;
        }

        // Load the plugin classes and the Subscribers
        $loadedPlugin = new $pluginClassName($this->container);
        //echo $loadedPlugin->getVersion();

        // Load the subscribers the plugin may have
        //print_r($loadedPlugin->getSubscribedEvents());
        $this->dispatcher->addSubscriber($loadedPlugin);

        $this->dispatcher->dispatch('plugin.loaded');
        //$this->dispatcher->dispatch('plugin.' . $pluginName . '.loaded');
    }

    protected function validPlugin($plugin)
    {

    }

    protected function getPluginBaseName($plugin)
    {
        $pluginName = basename($plugin, '.php');
        return $pluginName;
    }
}