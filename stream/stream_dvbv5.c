#include "osdep/io.h"
#include "misc/ctype.h"
#include "osdep/timer.h"

#include "stream.h"
#include "common/tags.h"
#include "options/m_option.h"
#include "options/m_config.h"
#include "options/options.h"
#include "options/path.h"

#include <linux/dvb/dmx.h>
#include "libdvbv5/dvb-file.h"
#include "libdvbv5/dvb-demux.h"
#include "libdvbv5/dvb-dev.h"
#include "libdvbv5/dvb-v5-std.h"
#include "libdvbv5/dvb-scan.h"
#include "libdvbv5/countries.h"

#include <unistd.h>
#include <strings.h>


#define DVB_BUF_SIZE    (4096 * 8 * 188)


typedef struct dvbv5_opts {
    int cfg_adapter;
    int cfg_frontend;
    int cfg_demux;
} dvbv5_opts_t;

typedef struct {
    struct dvb_open_descriptor *dvr_fd;
    dvbv5_opts_t *opts;
    struct m_config_cache *opts_cache;
} dvb_priv_t;

#define OPT_BASE_STRUCT struct dvbv5_opts
const struct m_sub_options stream_dvbv5_conf = {
    .opts = (const m_option_t[]) {
        {"adapter", OPT_INT(cfg_adapter), M_RANGE(0, 100)},
        {"frontend", OPT_INT(cfg_frontend), M_RANGE(0, 100)},
        {"demux", OPT_INT(cfg_demux), M_RANGE(0, 100)},
        {0}
    },
    .size = sizeof(struct dvbv5_opts),
    .defaults = &(const dvbv5_opts_t){
        .cfg_adapter = 0,
        .cfg_frontend = 0,
        .cfg_demux = 0,
    },
};

static int check_frontend(stream_t *stream, struct dvb_v5_fe_parms *parms)
{
    int rc;
    fe_status_t status = 0;
    static int timeout_flag = 0;
    do {
        rc = dvb_fe_get_stats(parms);
        if (rc) {
            MP_ERR(stream, "dvb_fe_get_stats failed");
            printf("usleep\n");
            usleep(1000000);
            continue;
        }

        status = 0;
        rc = dvb_fe_retrieve_stats(parms, DTV_STATUS, &status);
        if (status & FE_HAS_LOCK)
            break;
        usleep(1000000);
    } while (!timeout_flag);

    return status & FE_HAS_LOCK;
}

static int setup_frontend(stream_t *stream, struct dvb_v5_fe_parms *parms)
{
    int rc;

    rc = dvb_fe_set_parms(parms);
    if (rc < 0) {
        MP_ERR(stream, "dvb_fe_set_parms failed");
        return -1;
    }

    return 0;
}

void dvbv5_close(stream_t *stream);

void dvbv5_close(stream_t *stream)
{
}

static int dvbv5_stream_control(struct stream *s, int cmd, void *arg)
{
    MP_ERR(s, "stream control");
    return STREAM_UNSUPPORTED;
}

// copy_to_file from dvbv5-zap.c
static int dvbv5_streaming_read(stream_t *stream, void *buffer, int size)
{
    int r, pos = 0;

    dvb_priv_t *priv = stream->priv;

    r = dvb_dev_read(priv->dvr_fd, buffer, size);

    pos += r;

    return pos;
}

static int parse(stream_t *stream, struct dvb_v5_fe_parms *parms,
         int *vpid, int *apid, int *sid)
{
    struct mpv_global *global = stream->global;
    void *talloc_ctx;
    char *conf_file;
    char *channel;
    enum dvb_file_formats input_format;
    unsigned n_apid = 0, n_vpid = 0;
    channel = stream->path;

    input_format = dvb_parse_format("DVBV5");

    struct dvb_file *dvb_file;
    struct dvb_entry *entry;
    int i;
    uint32_t sys;

    /* This is used only when reading old formats */
    switch (parms->current_sys) {
    case SYS_DVBT:
    case SYS_DVBS:
    case SYS_DVBC_ANNEX_A:
    case SYS_ATSC:
        sys = parms->current_sys;
        break;
    case SYS_DVBC_ANNEX_C:
        sys = SYS_DVBC_ANNEX_A;
        break;
    case SYS_DVBC_ANNEX_B:
        sys = SYS_ATSC;
        break;
    case SYS_ISDBT:
    case SYS_DTMB:
        sys = SYS_DVBT;
        break;
    default:
        sys = SYS_UNDEFINED;
        break;
    }
    talloc_ctx = talloc_new(NULL);
    conf_file = mp_find_config_file(talloc_ctx, global, "channels.conf.dvbv5");
    dvb_file = dvb_read_file_format(conf_file, sys, input_format);
    if (!dvb_file) {
        return -2;
    }

    for (entry = dvb_file->first_entry; entry != NULL; entry = entry->next) {
        if (entry->channel && !strcmp(entry->channel, channel))
            break;
        if (entry->vchannel && !strcmp(entry->vchannel, channel))
            break;
    }
    /*
     * Give a second shot, using a case insensitive seek
     */
    if (!entry) {
        for (entry = dvb_file->first_entry; entry != NULL;
             entry = entry->next) {
            if (entry->channel && !strcasecmp(entry->channel, channel))
                break;
        }
    }

    if (!entry) {
        MP_ERR(stream, "Can't find channel");
        dvb_file_free(dvb_file);
        return -3;
    }

    /*
     * Both the DVBv5 format and the command line parameters may
     * specify the LNBf. If both have the definition, use the one
     * provided by the command line parameter, overriding the one
     * stored in the channel file.
     */
    if (entry->lnb && !parms->lnb) {
        int lnb = dvb_sat_search_lnb(entry->lnb);
        if (lnb == -1) {
            MP_ERR(stream, "unknown LNB %s\n", entry->lnb);
            dvb_file_free(dvb_file);
            return -1;
        }
        parms->lnb = dvb_sat_get_lnb(lnb);
    }

    if (parms->sat_number < 0 && entry->sat_number >= 0)
        parms->sat_number = entry->sat_number;

    if (entry->video_pid) {
        if (n_vpid < entry->video_pid_len)
            *vpid = entry->video_pid[n_vpid];
        else
            *vpid = entry->video_pid[0];
    }
    if (entry->audio_pid) {
        if (n_apid < entry->audio_pid_len)
            *apid = entry->audio_pid[n_apid];
        else
        *apid = entry->audio_pid[0];
    }
    if (entry->other_el_pid) {
        int ii, type = -1;
        for (ii = 0; ii < entry->other_el_pid_len; ii++) {
            if (type != entry->other_el_pid[ii].type) {
                type = entry->other_el_pid[ii].type;
                if (ii)
                    printf("\n");
                printf("service has pid type %02x: \n", type);

            }
        }
    }
    *sid = entry->service_id;

    /* First of all, set the delivery system */
    dvb_retrieve_entry_prop(entry, DTV_DELIVERY_SYSTEM, &sys);
    if (dvb_set_compat_delivery_system(parms, sys)) {
        MP_ERR(stream, "dvb_set_compat_delivery_system failed\n");
        return -4;
    }

    /* Copy data into parms */
    for (i = 0; i < entry->n_props; i++) {
        uint32_t data = entry->props[i].u.data;
        /* Don't change the delivery system */
        if (entry->props[i].cmd == DTV_DELIVERY_SYSTEM)
            continue;
        dvb_fe_store_parm(parms, entry->props[i].cmd, data);
        if (parms->current_sys == SYS_ISDBT) {
            dvb_fe_store_parm(parms, DTV_ISDBT_PARTIAL_RECEPTION, 0);
            dvb_fe_store_parm(parms, DTV_ISDBT_SOUND_BROADCASTING, 0);
            dvb_fe_store_parm(parms, DTV_ISDBT_LAYER_ENABLED, 0x07);
            if (entry->props[i].cmd == DTV_CODE_RATE_HP) {
                dvb_fe_store_parm(parms, DTV_ISDBT_LAYERA_FEC,
                          data);
                dvb_fe_store_parm(parms, DTV_ISDBT_LAYERB_FEC,
                          data);
                dvb_fe_store_parm(parms, DTV_ISDBT_LAYERC_FEC,
                          data);
            } else if (entry->props[i].cmd == DTV_MODULATION) {
                dvb_fe_store_parm(parms,
                          DTV_ISDBT_LAYERA_MODULATION,
                          data);
                dvb_fe_store_parm(parms,
                          DTV_ISDBT_LAYERB_MODULATION,
                          data);
                dvb_fe_store_parm(parms,
                          DTV_ISDBT_LAYERC_MODULATION,
                          data);
            }
        }
        if (parms->current_sys == SYS_ATSC &&
            entry->props[i].cmd == DTV_MODULATION) {
            if (data != VSB_8 && data != VSB_16)
                dvb_fe_store_parm(parms,
                          DTV_DELIVERY_SYSTEM,
                          SYS_DVBC_ANNEX_B);
        }
    }

    dvb_file_free(dvb_file);
    return 0;
}

static int dvbv5_open(stream_t *stream)
{
    struct dvb_device *dvb;
    struct dvb_v5_fe_parms *parms;
    struct dvb_dev_list *dvb_dev;
    static int verbose = 0;
    char *demux_dev, *dvr_dev, *dvr_fname;
    unsigned diseqc_wait = 0, freq_bpf = 0;
    int lna = 0;
    const char *cc = "NL"; // FIXME
    struct dvb_open_descriptor *dvr_fd = NULL;
    struct dvb_open_descriptor *audio_fd = NULL, *video_fd = NULL;
    int vpid = -1, apid = -1, sid = -1;

    dvb_priv_t *priv = NULL;
    stream->priv = talloc_zero(stream, dvb_priv_t);
    priv = stream->priv;
    priv->opts_cache = m_config_cache_alloc(stream, stream->global, &stream_dvbv5_conf);
    priv->opts = priv->opts_cache->opts;

    stream->fill_buffer = dvbv5_streaming_read;
    stream->close = dvbv5_close;
    stream->control = dvbv5_stream_control;
    stream->streaming = true;
    stream->demuxer = "lavf";
    stream->lavf_type = "mpegts";

    dvb = dvb_dev_alloc();
    if (!dvb)
    {
        return STREAM_ERROR;
    }

    dvb_dev_set_log(dvb, verbose, NULL);
    dvb_dev_find(dvb, NULL, NULL);
    parms = dvb->fe_parms;

    dvb_dev = dvb_dev_seek_by_adapter(dvb, priv->opts->cfg_adapter, priv->opts->cfg_demux, DVB_DEVICE_DEMUX);
    if (!dvb_dev) {
        dvb_dev_free(dvb);
        return STREAM_ERROR;
    }

    demux_dev = dvb_dev->sysname;

    dvb_dev = dvb_dev_seek_by_adapter(dvb, priv->opts->cfg_adapter, priv->opts->cfg_demux, DVB_DEVICE_DVR);
    if (!dvb_dev) {
        dvb_dev_free(dvb);
        return STREAM_ERROR;
    }
    dvr_dev = dvb_dev->sysname;
    dvr_fname = dvb_dev->path;

    dvb_dev = dvb_dev_seek_by_adapter(dvb, priv->opts->cfg_adapter, priv->opts->cfg_frontend, DVB_DEVICE_FRONTEND);
    if (!dvb_dev) {
        dvb_dev_free(dvb);
        return STREAM_ERROR;
    }

    if (!dvb_dev_open(dvb, dvb_dev->sysname, O_RDWR)) {
        dvb_dev_free(dvb);
        return STREAM_ERROR;
    }

    parms->diseqc_wait = diseqc_wait;
    parms->freq_bpf = freq_bpf;
    parms->lna = lna;


    dvb_fe_set_default_country(parms, cc);

    if (parse(stream, parms, &vpid, &apid, &sid)) {
        dvb_dev_free(dvb);
        return STREAM_ERROR;
    }

    if (setup_frontend(stream, parms) < 0) {
        dvb_dev_free(dvb);
        return STREAM_ERROR;
    }

      if (vpid >= 0) {
        video_fd = dvb_dev_open(dvb, demux_dev, O_RDWR);
        if (!video_fd) {
            MP_ERR(stream, "failed opening '%s'", demux_dev);
            return STREAM_ERROR;
        }

        dvb_dev_set_bufsize(video_fd, DVB_BUF_SIZE);

        if (dvb_dev_dmx_set_pesfilter(video_fd, vpid, DMX_PES_VIDEO,
            DMX_OUT_TS_TAP,
            64 * 1024) < 0) {
            return STREAM_ERROR;
        }
    }

    if (apid > 0) {
        audio_fd = dvb_dev_open(dvb, demux_dev, O_RDWR);
        if (!audio_fd) {
            MP_ERR(stream, "failed opening '%s'", demux_dev);
            return STREAM_ERROR;
        }
        if (dvb_dev_dmx_set_pesfilter(audio_fd, apid, DMX_PES_AUDIO,
                DMX_OUT_TS_TAP,
                64 * 1024) < 0) {
            return STREAM_ERROR;
        }
    }

    if (!check_frontend(stream, parms)) {

        MP_ERR(stream, "frontend doesn't lock");
        return STREAM_ERROR;
    }

    dvr_fd = dvb_dev_open(dvb, dvr_dev, O_RDONLY);
    if (!dvr_fd) {
        MP_ERR(stream, "failed opening '%s'", dvr_dev);
        return STREAM_ERROR;
    }

    priv->dvr_fd = dvr_fd;

    return STREAM_OK;
}

const stream_info_t stream_info_dvbv5 = {
    .name = "dvbv5",
    .open = dvbv5_open,
    .protocols = (const char *const[]){ "dvbv5", NULL },
    .stream_origin = STREAM_ORIGIN_UNSAFE,
};
