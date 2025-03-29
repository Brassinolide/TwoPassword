#include "gui.h"
#include "memsafe.h"
#include "config.h"

int main() {
	config.load_config_file();

	if (config.config_get_int("memsafe", 0, 2, 0) == 2) {
		disable_memfree();
	}

	RenderGUI();
}
