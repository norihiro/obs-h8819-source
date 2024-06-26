#include <obs-module.h>
#include "plugin-macros.generated.h"
#include "source.h"
#include "capdev.h"

struct source_s
{
	obs_source_t *context;

	// properties
	char *device_name;
	int channel_l;
	int channel_r;

	// internal data
	capdev_t *capdev;
};

static const char *get_name(void *type_data)
{
	UNUSED_PARAMETER(type_data);
	return obs_module_text("h8819 Audio");
}

static void device_name_enum_cb(const char *name, const char *description, void *param)
{
	obs_property_t *prop = param;

	obs_property_list_add_string(prop, description, name);
}

static obs_properties_t *get_properties(void *data)
{
	UNUSED_PARAMETER(data);
	obs_properties_t *props = obs_properties_create();
	obs_property_t *prop;

	prop = obs_properties_add_list(props, "device_name", obs_module_text("Ethernet device"), OBS_COMBO_TYPE_LIST,
				       OBS_COMBO_FORMAT_STRING);
	capdev_enum_devices(device_name_enum_cb, prop);
	obs_properties_add_int(props, "channel_l", obs_module_text("Channel Left"), 1, 40, 1);
	obs_properties_add_int(props, "channel_r", obs_module_text("Channel Right"), 1, 40, 1);
#ifdef ENABLE_ASYNC_COMPENSATION
	obs_properties_add_bool(props, "async_compensation", obs_module_text("AsyncCompensation"));
#endif

	return props;
}

static void update_device(struct source_s *s, const char *device_name, int channel_l, int channel_r)
{
	capdev_t *old_dev = s->capdev;

	s->capdev = capdev_find_or_create(device_name);

	bfree(s->device_name);
	s->device_name = bstrdup(device_name);

	if (old_dev)
		capdev_unlink_source(old_dev, s);

	int cc[3] = {channel_l, channel_r, -1};
	capdev_link_source(s->capdev, s, cc);

	s->channel_l = channel_l;
	s->channel_r = channel_r;

	if (old_dev)
		capdev_release(old_dev);
}

static void update_channels(struct source_s *s, int channel_l, int channel_r)
{
	int cc[3] = {channel_l, channel_r, -1};
	if (s->capdev)
		capdev_update_source(s->capdev, s, cc);

	s->channel_l = channel_l;
	s->channel_r = channel_r;
}

static void update(void *data, obs_data_t *settings)
{
	struct source_s *s = data;

	const char *device_name = obs_data_get_string(settings, "device_name");
	int channel_l = obs_data_get_int(settings, "channel_l") - 1;
	int channel_r = obs_data_get_int(settings, "channel_r") - 1;

	if (channel_l < 0)
		channel_l = 0;
	if (channel_l >= 40)
		channel_l = 40 - 1;
	if (channel_r < 0)
		channel_r = 0;
	if (channel_r >= 40)
		channel_r = 40 - 1;

	if (device_name && (!s->device_name || strcmp(device_name, s->device_name)))
		update_device(s, device_name, channel_l, channel_r);

	if (channel_l != s->channel_l || channel_r != s->channel_r)
		update_channels(s, channel_l, channel_r);

#ifdef ENABLE_ASYNC_COMPENSATION
	obs_source_set_async_compensation(s->context, obs_data_get_bool(settings, "async_compensation"));
#endif
}

static void *create(obs_data_t *settings, obs_source_t *source)
{
	struct source_s *s = bzalloc(sizeof(struct source_s));
	s->context = source;

	update(s, settings);

	return s;
}

static void destroy(void *data)
{
	struct source_s *s = data;

	if (s->capdev) {
		capdev_unlink_source(s->capdev, s);
		capdev_release(s->capdev);
	}

	bfree(s->device_name);
	bfree(s);
}

void source_add_audio(source_t *s, float **data, int n_samples, uint64_t timestamp)
{
	struct obs_source_audio out = {
		.speakers = 2,
		.samples_per_sec = 48000, // TODO: retrieve from the packet
		.format = AUDIO_FORMAT_FLOAT_PLANAR,
		.frames = n_samples,
		.timestamp = timestamp,
	};
	for (int i = 0; i < 2; i++)
		out.data[i] = (void *)data[i];

	obs_source_output_audio(s->context, &out);
}

const struct obs_source_info src_info = {
	.id = ID_PREFIX "source",
	.type = OBS_SOURCE_TYPE_INPUT,
	.output_flags = OBS_SOURCE_AUDIO | OBS_SOURCE_DO_NOT_DUPLICATE,
	.get_name = get_name,
	.create = create,
	.destroy = destroy,
	.update = update,
	.get_properties = get_properties,
	.icon_type = OBS_ICON_TYPE_AUDIO_INPUT,
};
