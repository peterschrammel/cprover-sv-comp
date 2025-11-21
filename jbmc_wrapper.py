#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import re
import shutil
import hashlib
from datetime import datetime
from tool_wrapper import ToolWrapper

class JBMCWrapper(ToolWrapper):
    """JBMC-specific wrapper implementation"""

    def __init__(self):
        super().__init__()
        self.tool_binary = "./jbmc-binary"
        self.tool_name = "JBMC"
        self.nondet_values = {}
        self.find_options = "-name '*.java'"
        self.jvm_home = "/usr/lib/jvm/java-8-openjdk-amd64"

    def print_version(self):
        """Print JBMC version"""
        subprocess.run([self.tool_binary, "--version"])

    def run(self):
        """Run fuzzing first, then JBMC"""
        # Create directories
        classes_dir, src_dir = self._create_directories()

        # Process benchmark files
        has_nondet = self._process_benchmark_files_for_fuzzing(src_dir)

        # Compile benchmark files
        self._compile_benchmark_files_for_fuzzing(classes_dir)

        # Try running with Java first
        ec = self._run_fuzzing(classes_dir, has_nondet)

        if ec == 42:
            # Process benchmark files for JBMC
            task_jar = self._process_benchmark_files_for_jbmc(classes_dir)

            # Run JBMC
            ec = self._run_jbmc(task_jar)

        return ec

    def _create_directories(self):
        """Create necessary directories for compilation and source files"""
        classes_dir = os.path.join(self.bm_dir, "classes")
        src_dir = os.path.join(self.bm_dir, "src", "org", "sosy_lab", "sv_benchmarks")
        os.makedirs(classes_dir, exist_ok=True)
        os.makedirs(src_dir, exist_ok=True)
        return classes_dir, src_dir

    def _process_benchmark_files_for_fuzzing(self, src_dir):
        """Process benchmark files for fuzzing

        Args:
            src_dir: The source directory path

        Returns:
            has_nondet boolean
        """
        has_nondet = False
        verifier_file = None

        for i, bm_file in enumerate(self.benchmarks):
            if "Verifier.java" in bm_file:
                verifier_file = os.path.join(src_dir, "Verifier.java")
                shutil.copy(bm_file, verifier_file)

                # Also copy ObjectFactory.java if it exists
                object_factory = os.path.join(os.path.dirname(bm_file), "ObjectFactory.java")
                if os.path.exists(object_factory):
                    shutil.copy(object_factory, os.path.join(src_dir, "ObjectFactory.java"))

                self.benchmarks[i] = verifier_file
            else:
                with open(bm_file, 'r') as f:
                    if "Verifier.nondet" in f.read():
                        has_nondet = True

        if verifier_file:
            # Patch Verifier.java
            self._instantiate_inputs_for_fuzzing(verifier_file)

        return has_nondet

    def _instantiate_inputs_for_fuzzing(self, verifier_file):
        """Patch the Verifier.java file and track nondet values"""
        with open(verifier_file, 'r') as f:
            content = f.read()

        # Distinguish assumption from assertion failures
        content = content.replace('Runtime.getRuntime().halt(1);', 'Runtime.getRuntime().halt(2);')

        # Determinize random values and track what we're setting
        self.nondet_values = {}

        # Map of replacements and their corresponding nondet function info
        replacements = [
            ('(byte) (new Random().nextInt())', '(byte) 11', 'nondetByte', 'B'),
            ('(char) (new Random().nextInt())', '(char) 11', 'nondetChar', 'C'),
            ('(short) (new Random().nextInt())', '(short) 11', 'nondetShort', 'S'),
            ('new Random().nextInt()', '11', 'nondetInt', 'I'),
            ('new Random().nextBoolean()', 'false', 'nondetBoolean', 'Z'),
            ('new Random().nextLong()', '11L', 'nondetLong', 'J'),
            ('new Random().nextFloat()', '11.0f', 'nondetFloat', 'F'),
            ('new Random().nextDouble()', '11.0', 'nondetDouble', 'D')
        ]

        for old, new, func_name, type_sig in replacements:
            if old in content:
                content = content.replace(old, new)
                if func_name not in self.nondet_values:
                    self.nondet_values[func_name] = {
                        'value': new,
                        'type_sig': type_sig
                    }

        # Special handling for string
        if 'return new String(bytes);' in content:
            content = content.replace('return new String(bytes);', 'return "JBMC at SV-COMP 2026";')
            self.nondet_values['nondetString'] = {
                'value': 'JBMC at SV-COMP 2026',
                'type_sig': 'Ljava/lang/String;'
            }

        with open(verifier_file, 'w') as f:
            f.write(content)

    def _extract_nondet_assumptions(self):
        """Extract information about nondet calls from all benchmark files

        Returns:
            List of nondet assumption dicts with file, line, function, scope, and value
        """
        assumptions = []

        # Pattern to match Verifier.nondet* calls
        nondet_pattern = re.compile(r'Verifier\.nondet(\w+)\(\)')

        for bm_file in self.benchmarks:
            with open(bm_file, 'r') as f:
                lines = f.readlines()

            # Get relative path for the file
            if 'common/org/sosy_lab/sv_benchmarks' in bm_file:
                origin_file = bm_file.split('common/')[-1]
            else:
                origin_file = os.path.basename(bm_file)

            for line_num, line in enumerate(lines, 1):
                match = nondet_pattern.search(line)
                if match:
                    func_name = 'nondet' + match.group(1)

                    # Skip if we don't have a value for this function
                    if func_name not in self.nondet_values:
                        continue

                    value_info = self.nondet_values[func_name]

                    # Construct the scope string
                    scope = f'java::org.sosy_lab.sv_benchmarks.Verifier.{func_name}:(){value_info["type_sig"]}'

                    assumptions.append({
                        'file': origin_file,
                        'line': line_num,
                        'function': func_name,
                        'scope': scope,
                        'value': value_info['value']
                    })

        return assumptions

    def _compile_benchmark_files_for_fuzzing(self, classes_dir):
        """Compile Java benchmark files for fuzzing

        Args:
            classes_dir: The directory where compiled classes should be placed
        """
        javac_cmd = [
            os.path.join(self.jvm_home, "bin", "javac"),
            "-g",
            "-cp", classes_dir,
            "-d", classes_dir
        ] + self.benchmarks

        subprocess.run(javac_cmd, check=True)

    def _run_fuzzing(self, classes_dir, has_nondet):
        """Try running the Java program directly"""
        # Set Java options
        java_options = "-ea" if self.prop == "unreach_call" else ""

        java_cmd = [os.path.join(self.jvm_home, "bin", "java")]
        if java_options:
            java_cmd.append(java_options)
        java_cmd.extend(["-cp", classes_dir, "Main"])

        with open(f"{self.log_file}.latest", 'w') as log:
            try:
                result = subprocess.run(java_cmd, stdout=log, stderr=subprocess.STDOUT, timeout=10)
                ecr = result.returncode
            except subprocess.TimeoutExpired:
                ecr = 124

        ec = 42

        # Check for errors
        if ecr == 1:
            with open(f"{self.log_file}.latest", 'r') as log:
                log_content = log.read()

            error_patterns = [
                r"java\.lang\.StackOverflowError",
                r"java\.lang\.OutOfMemoryError",
                r"Error: Could not find or load main class",
                r"Error: Main method not found in class"
            ]

            if self.prop == "unreach_call":
                error_patterns.append(r"Exception in thread \"main\" java\..*Exception")
            elif self.prop == "runtime-exception":
                error_patterns.extend([
                    r"Exception in thread \"main\" java\.lang\.Exception",
                    r"Exception in thread \"main\" java\.io\.IOException",
                    r"Exception in thread \"main\" java\.lang\.NoSuchFieldException",
                    r"Exception in thread \"main\" java\.lang\.InterruptedException"
                ])
            else:
                error_patterns.append(r"Exception in thread \"main\" java\.lang\.AssertionError")

            if any(re.search(pattern, log_content) for pattern in error_patterns):
                ecr = 42

        # Actual failure found
        if ecr == 1:
            ec = 10
            # Extract nondet assumptions and create witness
            nondet_assumptions = self._extract_nondet_assumptions()
            self._create_minimal_witness(nondet_assumptions=nondet_assumptions)
            shutil.copy(f"{self.log_file}.latest", f"{self.log_file}.ok")
        elif ecr == 0:
            # No assertion failure, but might be deterministic
            if not has_nondet:
                ec = 0
                shutil.copy(f"{self.log_file}.latest", f"{self.log_file}.ok")

        return ec


    def _create_minimal_witness(self, specification=None, nondet_assumptions=None):
        """Create a minimal GraphML witness

        Args:
            specification: The property specification string from the property file
            nondet_assumptions: List of dicts containing nondet function call information:
                [{'file': 'org/sosy_lab/sv_benchmarks/Verifier.java',
                  'line': 50,
                  'function': 'nondetInt',
                  'scope': 'java::org.sosy_lab.sv_benchmarks.Verifier.nondetInt:()I',
                  'value': '11'},
                 ...]
        """
        if specification is None:
            # Read from property file
            with open(self.prop_file, 'r') as f:
                specification = f.read().strip()

        # Calculate program hash
        with open(self.benchmarks[0], 'rb') as f:
            program_hash = hashlib.sha256(f.read()).hexdigest()

        # Get creation time
        creation_time = datetime.now().isoformat()

        # Build nodes and edges
        nodes_edges = []

        # Always have a sink node
        nodes_edges.append('    <node id="sink"/>')

        # Start with entry node
        nodes_edges.append('    <node id="1">')
        nodes_edges.append('      <data key="entry">true</data>')
        nodes_edges.append('    </node>')

        current_node = 1

        # Add edges for each nondet assumption
        if nondet_assumptions:
            for assumption in nondet_assumptions:
                next_node = current_node + 1
                nodes_edges.append(f'    <edge source="{current_node}" target="{next_node}">')
                nodes_edges.append(f'      <data key="originfile">{assumption["file"]}</data>')
                nodes_edges.append(f'      <data key="startline">{assumption["line"]}</data>')
                nodes_edges.append('      <data key="threadId">0</data>')

                # Format the assumption based on function type
                if assumption["function"] == "nondetString":
                    nodes_edges.append(f'      <data key="assumption">return_tmp0 = "{assumption["value"]}";</data>')
                else:
                    nodes_edges.append(f'      <data key="assumption">return_tmp0 = {assumption["value"]};</data>')

                nodes_edges.append(f'      <data key="assumption.scope">{assumption["scope"]}</data>')
                nodes_edges.append('    </edge>')

                # Add the next node
                nodes_edges.append(f'    <node id="{next_node}"/>')
                current_node = next_node

        # Mark the last node as violation node
        if current_node > 1:
            # Replace the last node with violation node
            nodes_edges[-1] = f'    <node id="{current_node}">'
            nodes_edges.append('      <data key="violation">true</data>')
            nodes_edges.append('    </node>')

        witness_content = f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <key attr.name="originFileName" attr.type="string" for="edge" id="originfile">
    <default>&lt;command-line&gt;</default>
  </key>
  <key attr.name="invariant" attr.type="string" for="node" id="invariant"/>
  <key attr.name="invariant.scope" attr.type="string" for="node" id="invariant.scope"/>
  <key attr.name="isViolationNode" attr.type="boolean" for="node" id="violation">
    <default>false</default>
  </key>
  <key attr.name="isEntryNode" attr.type="boolean" for="node" id="entry">
    <default>false</default>
  </key>
  <key attr.name="isSinkNode" attr.type="boolean" for="node" id="sink">
    <default>false</default>
  </key>
  <key attr.name="enterLoopHead" attr.type="boolean" for="edge" id="enterLoopHead">
    <default>false</default>
  </key>
  <key attr.name="cyclehead" attr.type="boolean" for="node" id="cyclehead">
    <default>false</default>
  </key>
  <key attr.name="threadId" attr.type="int" for="edge" id="threadId">
    <default>0</default>
  </key>
  <key attr.name="createThread" attr.type="int" for="edge" id="createThread">
    <default>0</default>
  </key>
  <key attr.name="sourcecodeLanguage" attr.type="string" for="graph" id="sourcecodelang"/>
  <key attr.name="programFile" attr.type="string" for="graph" id="programfile"/>
  <key attr.name="programHash" attr.type="string" for="graph" id="programhash"/>
  <key attr.name="specification" attr.type="string" for="graph" id="specification"/>
  <key attr.name="architecture" attr.type="string" for="graph" id="architecture"/>
  <key attr.name="producer" attr.type="string" for="graph" id="producer"/>
  <key attr.name="creationtime" attr.type="string" for="graph" id="creationtime"/>
  <key attr.name="startline" attr.type="int" for="edge" id="startline"/>
  <key attr.name="control" attr.type="string" for="edge" id="control"/>
  <key attr.name="assumption" attr.type="string" for="edge" id="assumption"/>
  <key attr.name="assumption.resultfunction" attr.type="string" for="edge" id="assumption.resultfunction"/>
  <key attr.name="assumption.scope" attr.type="string" for="edge" id="assumption.scope"/>
  <key attr.name="enterFunction" attr.type="string" for="edge" id="enterFunction"/>
  <key attr.name="returnFromFunction" attr.type="string" for="edge" id="returnFrom"/>
  <key attr.name="witness-type" attr.type="string" for="graph" id="witness-type"/>
  <graph edgedefault="directed">
    <data key="witness-type">violation_witness</data>
    <data key="producer">{self.tool_name}</data>
    <data key="specification">{specification}</data>
    <data key="programfile">{self.benchmarks[0]}</data>
    <data key="programhash">{program_hash}</data>
    <data key="architecture">{self.bit_width}bit</data>
    <data key="creationtime">{creation_time}</data>
    <data key="sourcecodelang">Java</data>
{chr(10).join(nodes_edges)}
  </graph>
</graphml>
'''
        with open(f"{self.log_file}.witness", 'w') as f:
            f.write(witness_content)

    def _process_benchmark_files_for_jbmc(self, classes_dir):
        """Process benchmark files for JBMC analysis

        Args:
            classes_dir: Directory containing compiled classes

        Returns:
            str: Path to the created JAR file
        """
        # Remove Verifier.class
        verifier_class = os.path.join(classes_dir, "org", "sosy_lab", "sv_benchmarks", "Verifier.class")
        if os.path.exists(verifier_class):
            os.remove(verifier_class)

        # Create JAR file
        task_jar = os.path.join(self.bm_dir, "task.jar")
        jar_cmd = ["jar", "-cfe", task_jar, "Main", "-C", classes_dir, "."]
        subprocess.run(jar_cmd, check=True)

        # Log checksums
        with open(f"{self.log_file}.ok", 'w') as log:
            for file in [task_jar, "jbmc", "jbmc-binary", "core-models.jar", "cprover-api.jar"]:
                if os.path.exists(file):
                    result = subprocess.run(["sha1sum", file], capture_output=True, text=True)
                    log.write(result.stdout)

        return task_jar

    def _run_jbmc(self, task_jar):
        """Run JBMC analysis"""

        more_options = "--java-threading --throw-runtime-exceptions --max-nondet-string-length 125 --classpath core-models.jar:cprover-api.jar"

        # Adjust property options
        if self.prop == "unreach_call":
            self.property_options += " --throw-assertion-error --uncaught-exception-check-only-for java.lang.AssertionError"
        elif self.prop == "termination":
            self.property_options += " --no-assertions --no-self-loops-to-assumptions"
        elif self.prop == "runtime-exception":
            self.property_options += " --no-assertions"

        # Run with increasing unwind bounds
        unwind_bounds = [2, 6, 10, 15, 20, 25, 30, 35, 45, 60, 100, 150, 200, 300, 400, 500, 1025, 2049, 268435456]
        timeout_seconds = 875
        memory_limit = 15000000  # in KB

        start_time = time.time()
        ec = 42

        for unwind in unwind_bounds:
            if time.time() - start_time > timeout_seconds:
                break

            with open(f"{self.log_file}.latest", 'w') as log:
                log.write(f"Unwind: {unwind}\n")

            # Run without unwinding assertions
            jbmc_cmd = [
                self.tool_binary,
                *more_options.split(),
                "--graphml-witness", f"{self.log_file}.witness",
                "--no-unwinding-assertions",
                "--unwind", str(unwind),
                "--stop-on-fail",
                f"--{self.bit_width}",
                "--object-bits", self.obj_bits,
                *self.property_options.split(),
                "--function", self.entry,
                "-jar", task_jar
            ]
            print(" ".join(jbmc_cmd))

            try:
                result = subprocess.run(
                    ["bash", "-c", f"ulimit -v {memory_limit}; exec " + " ".join(f'"{arg}"' for arg in jbmc_cmd)],
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds - (time.time() - start_time)
                )

                with open(f"{self.log_file}.latest", 'a') as log:
                    log.write(result.stdout)
                    log.write(result.stderr)

                ec = result.returncode

                # Check for successful verification
                if ec == 0:
                    if "VERIFICATION SUCCESSFUL" not in result.stdout.split('\n')[-10:]:
                        ec = 1
                    else:
                        # Double-check with unwinding assertions
                        check_cmd = jbmc_cmd.copy()
                        check_cmd[check_cmd.index("--no-unwinding-assertions")] = "--unwinding-assertions"

                        check_result = subprocess.run(
                            ["bash", "-c", f"ulimit -v {memory_limit}; exec " + " ".join(f'"{arg}"' for arg in check_cmd)],
                            capture_output=True,
                            timeout=timeout_seconds - (time.time() - start_time)
                        )

                        if check_result.returncode != 0:
                            ec = 42

                # Check for verification failure
                elif ec == 10:
                    if "VERIFICATION FAILED" not in result.stdout.split('\n')[-10:]:
                        ec = 1

                # Append to log
                with open(f"{self.log_file}.ok", 'a') as log:
                    with open(f"{self.log_file}.latest", 'r') as latest:
                        log.write(latest.read())

                if ec in [0, 10]:
                    break
                elif ec != 42:
                    break

            except subprocess.TimeoutExpired:
                ec = 42
                with open(f"{self.log_file}.ok", 'a') as log:
                    if os.path.exists(f"{self.log_file}.latest"):
                        with open(f"{self.log_file}.latest", 'r') as latest:
                            log.write(latest.read())
                break
            except Exception:
                ec = 42
                continue

        # Final update if needed
        if not os.path.exists(f"{self.log_file}.ok"):
            if os.path.exists(f"{self.log_file}.latest"):
                with open(f"{self.log_file}.ok", 'w') as log:
                    with open(f"{self.log_file}.latest", 'r') as latest:
                        log.write(latest.read())
            ec = 42

        return ec


if __name__ == "__main__":
    wrapper = JBMCWrapper()
    wrapper.parse_arguments(sys.argv[1:])
    wrapper.execute()
