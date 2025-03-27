#include "gui.h"
#include "memsafe.h"
#include "setting.h"

int main() {
	if (get_config_int(L"memsafe", 0) == 2) {
		disable_memfree();
	}

	RenderGUI();
}
