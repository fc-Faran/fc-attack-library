class AttackLibDependency {
    [String] $description
    [String] $prereq_command
    [String] $get_prereq_command
}

class AttackLibInputArgument {
    [String] $description
    [String] $type
    [String] $default
}

class AttackLibExecutorBase {
    [String] $name
    [Bool] $elevation_required

    # Implemented to facilitate improved PS object display
    [String] ToString() {
        return $this.Name
    }
}

class AttackLibExecutorDefault : AttackLibExecutorBase {
    [String] $command
    [String] $cleanup_command
}

class AttackLibExecutorManual : AttackLibExecutorBase {
    [String] $steps
    [String] $cleanup_command
}

class AttackLibTest {
    [String] $name
    [String] $auto_generated_guid
    [String] $description
    [String[]] $supported_platforms
    # I wish this didn't have to be a hashtable but I don't
    # want to change the schema and introduce a breaking change.
    [Hashtable] $input_arguments
    [String] $dependency_executor_name
    [AttackLibDependency[]] $dependencies
    [AttackLibExecutorBase] $executor

    # Implemented to facilitate improved PS object display
    [String] ToString() {
        return $this.name
    }
}

class AttackLibTechnique {
    [String[]] $attack_technique
    [String] $display_name
    [AttackLibTest[]] $atomic_tests
}
