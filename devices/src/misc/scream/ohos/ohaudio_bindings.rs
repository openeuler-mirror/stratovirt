// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

/// The call was successful.
pub const OH_AUDIO_STREAM_RESULT_AUDIOSTREAM_SUCCESS: OhAudioStreamResult = 0;
#[allow(unused)]
/// This means that the function was executed with an invalid input parameter.
pub const OH_AUDIO_STREAM_RESULT_AUDIOSTREAM_ERROR_INVALID_PARAM: OhAudioStreamResult = 1;
#[allow(unused)]
/// Execution status exception
pub const OH_AUDIO_STREAM_RESULT_AUDIOSTREAM_ERROR_ILLEGAL_STATE: OhAudioStreamResult = 2;
#[allow(unused)]
/// An system error has occurred
pub const OH_AUDIO_STREAM_RESULT_AUDIOSTREAM_ERROR_SYSTEM: OhAudioStreamResult = 3;
/// Define the result of the function execution.
///
/// @since 10
pub type OhAudioStreamResult = ::std::os::raw::c_uint;

/// The type for audio stream is renderer.
pub const OH_AUDIO_STREAM_TYPE_AUDIOSTREAM_TYPE_RERNDERER: OhAudioStreamType = 1;
/// The type for audio stream is capturer.
pub const OH_AUDIO_STREAM_TYPE_AUDIOSTREAM_TYPE_CAPTURER: OhAudioStreamType = 2;
/// Define the audio stream type.
///
/// @since 10
pub type OhAudioStreamType = ::std::os::raw::c_uint;

#[allow(unused)]
pub const OH_AUDIO_STREAM_SAMPLE_FORMAT_AUDIOSTREAM_SAMPLE_U8: OhAudioStreamSampleFormat = 0;
pub const OH_AUDIO_STREAM_SAMPLE_FORMAT_AUDIOSTREAM_SAMPLE_S16_LE: OhAudioStreamSampleFormat = 1;
pub const OH_AUDIO_STREAM_SAMPLE_FORMAT_AUDIOSTREAM_SAMPLE_S24_LE: OhAudioStreamSampleFormat = 2;
pub const OH_AUDIO_STREAM_SAMPLE_FORMAT_AUDIOSTREAM_SAMPLE_S32_LE: OhAudioStreamSampleFormat = 3;
#[allow(unused)]
pub const OH_AUDIO_STREAM_SAMPLE_FORMAT_AUDIOSTREAM_SAMPLE_F32_LE: OhAudioStreamSampleFormat = 4;
/// Define the audio stream sample format.
///
/// @since 10
pub type OhAudioStreamSampleFormat = ::std::os::raw::c_uint;

#[allow(unused)]
pub const OH_AUDIO_STREAM_ENCODING_TYPE_AUDIOSTREAM_ENCODING_TYPE_RAW: OhAudioStreamEncodingType =
    0;
/// Define the audio encoding type.
///
/// @since 10
pub type OhAudioStreamEncodingType = ::std::os::raw::c_uint;

#[allow(unused)]
pub const OH_AUDIO_STREAM_USAGE_AUDIOSTREAM_USAGE_UNKNOWN: OhAudioStreamUsage = 0;
#[allow(unused)]
pub const OH_AUDIO_STREAM_USAGE_AUDIOSTREAM_USAGE_MEDIA: OhAudioStreamUsage = 1;
#[allow(unused)]
pub const OH_AUDIO_STREAM_USAGE_AUDIOSTREAM_USAGE_COMMUNICATION: OhAudioStreamUsage = 2;
/// Define the audio stream usage.
/// Audio stream usage is used to describe what work scenario
/// the current stream is used for.
///
/// @since 10
pub type OhAudioStreamUsage = ::std::os::raw::c_uint;

#[allow(unused)]
pub const OH_AUDIO_STREAM_CONTENT_AUDIOSTREAM_CONTENT_TYPE_UNKNOWN: OhAudioStreamContent = 0;
#[allow(unused)]
pub const OH_AUDIO_STREAM_CONTENT_AUDIOSTREAM_CONTENT_TYPE_SPEECH: OhAudioStreamContent = 1;
#[allow(unused)]
pub const OH_AUDIO_STREAM_CONTENT_AUDIOSTREAM_CONTENT_TYPE_MUSIC: OhAudioStreamContent = 2;
#[allow(unused)]
pub const OH_AUDIO_STREAM_CONTENT_AUDIOSTREAM_CONTENT_TYPE_MOVIE: OhAudioStreamContent = 3;
/// Define the audio stream content.
/// Audio stream content is used to describe the stream data type.
///
/// @since 10
pub type OhAudioStreamContent = ::std::os::raw::c_uint;

#[allow(unused)]
/// This is a normal audio scene.
pub const OH_AUDIO_STREAM_LATENCY_MODE_NORMAL: OhAudioStreamLatencyMode = 0;
#[allow(unused)]
pub const OH_AUDIO_STREAM_LATENCY_MODE_FAST: OhAudioStreamLatencyMode = 1;
/// Define the audio latency mode.
///
/// @since 10
pub type OhAudioStreamLatencyMode = ::std::os::raw::c_uint;

#[allow(unused)]
/// The invalid state.
pub const OH_AUDIO_STREAM_STATE_AUDIOSTREAM_STATE_INVALID: OhAudioStreamState = -1;
#[allow(unused)]
/// The prepared state.
pub const OH_AUDIO_STREAM_STATE_AUDIOSTREAM_STATE_PREPARED: OhAudioStreamState = 0;
#[allow(unused)]
/// The stream is running.
pub const OH_AUDIO_STREAM_STATE_AUDIOSTREAM_STATE_RUNNING: OhAudioStreamState = 1;
#[allow(unused)]
/// The stream is stopped.
pub const OH_AUDIO_STREAM_STATE_AUDIOSTREAM_STATE_STOPPED: OhAudioStreamState = 2;
#[allow(unused)]
/// The stream is paused.
pub const OH_AUDIO_STREAM_STATE_AUDIOSTREAM_STATE_PAUSED: OhAudioStreamState = 3;
#[allow(unused)]
/// The stream is released.
pub const OH_AUDIO_STREAM_STATE_AUDIOSTREAM_STATE_RELEASED: OhAudioStreamState = 4;
#[allow(unused)]
/// The audio stream states
///
/// @since 10"
pub type OhAudioStreamState = ::std::os::raw::c_int;

#[allow(unused)]
pub const OH_AUDIO_STREAM_SOURCE_TYPE_AUDIOSTREAM_SOURCE_TYPE_INVALID: OHAudioStreamSourceType = -1;
#[allow(unused)]
pub const OH_AUDIO_STREAM_SOURCE_TYPE_AUDIOSTREAM_SOURCE_TYPE_MIC: OHAudioStreamSourceType = 0;
#[allow(unused)]
pub const OH_AUDIO_STREAM_SOURCE_TYPE_AUDIOSTREAM_SOURCE_TYPE_VOICE_RECOGNITION:
    OHAudioStreamSourceType = 1;
#[allow(unused)]
pub const OH_AUDIO_STREAM_SOURCE_TYPE_AUDIOSTREAM_SOURCE_TYPE_VOICE_COMMUNICATION:
    OHAudioStreamSourceType = 7;
/// Defines the audio source type.
///
///  @since 10
pub type OHAudioStreamSourceType = ::std::os::raw::c_int;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OH_AudioStreamBuilderStruct {
    _unused: [u8; 0],
}
/// Declaring the audio stream builder.
/// The instance of builder is used for creating audio stream.
///
/// @since 10
pub type OhAudioStreamBuilder = OH_AudioStreamBuilderStruct;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OH_AudioRendererStruct {
    _unused: [u8; 0],
}
/// Declaring the audio renderer stream.
/// The instance of renderer stream is used for playing audio data.
///
/// @since 10
pub type OhAudioRenderer = OH_AudioRendererStruct;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OH_AudioCapturerStruct {
    _unused: [u8; 0],
}
/// Declaring the audio capturer stream.
/// The instance of renderer stream is used for capturing audio data.
///
/// @since 10
pub type OhAudioCapturer = OH_AudioCapturerStruct;

type PlaceHolderFn = std::option::Option<unsafe extern "C" fn() -> i32>;

/// Declaring the callback struct for renderer stream.
///
/// @since 10
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct OhAudioRendererCallbacks {
    /// This function pointer will point to the callback function that
    /// is used to write audio data
    pub oh_audio_renderer_on_write_data: ::std::option::Option<
        extern "C" fn(
            renderer: *mut OhAudioRenderer,
            userData: *mut ::std::os::raw::c_void,
            buffer: *mut ::std::os::raw::c_void,
            length: i32,
        ) -> i32,
    >,
    pub oh_audio_renderer_on_stream_event: PlaceHolderFn,
    pub oh_audio_renderer_on_interrpt_event: PlaceHolderFn,
    pub oh_audio_renderer_on_error: PlaceHolderFn,
}

/// Declaring the callback struct for capturer stream.
///
/// @since 10
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct OhAudioCapturerCallbacks {
    /// This function pointer will point to the callback function that
    /// is used to read audio data.
    pub oh_audio_capturer_on_read_data: ::std::option::Option<
        extern "C" fn(
            capturer: *mut OhAudioCapturer,
            userData: *mut ::std::os::raw::c_void,
            buffer: *mut ::std::os::raw::c_void,
            length: i32,
        ) -> i32,
    >,
    pub oh_audio_capturer_on_stream_event: PlaceHolderFn,
    pub oh_audio_capturer_on_interrpt_event: PlaceHolderFn,
    pub oh_audio_capturer_on_error: PlaceHolderFn,
}

#[allow(unused)]
#[link(name = "ohaudio")]
extern "C" {
    pub fn OH_AudioRenderer_Release(renderer: *mut OhAudioRenderer) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_Start(renderer: *mut OhAudioRenderer) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_Pause(renderer: *mut OhAudioRenderer) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_Stop(renderer: *mut OhAudioRenderer) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_Flush(renderer: *mut OhAudioRenderer) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_GetCurrentState(
        renderer: *mut OhAudioRenderer,
        state: *mut OhAudioStreamState,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_GetSamplingRate(
        renderer: *mut OhAudioRenderer,
        rate: *mut i32,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_GetStreamId(
        renderer: *mut OhAudioRenderer,
        streamId: *mut u32,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_GetChannelCount(
        renderer: *mut OhAudioRenderer,
        channelCount: *mut i32,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_GetSampleFormat(
        renderer: *mut OhAudioRenderer,
        sampleFormat: *mut OhAudioStreamSampleFormat,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_GetLatencyMode(
        renderer: *mut OhAudioRenderer,
        latencyMode: *mut OhAudioStreamLatencyMode,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_GetRendererInfo(
        renderer: *mut OhAudioRenderer,
        usage: *mut OhAudioStreamUsage,
        content: *mut OhAudioStreamContent,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioRenderer_GetEncodingType(
        renderer: *mut OhAudioRenderer,
        encodingType: *mut OhAudioStreamEncodingType,
    ) -> OhAudioStreamResult;
    /// Create a streamBuilder can be used to open a renderer or capturer client.
    ///
    /// OH_AudioStreamBuilder_Destroy() must be called when you are done using the builder.
    ///
    /// @since 10
    ///
    /// @param builder The builder reference to the created result.
    /// @param type The stream type to be created. {@link #AUDIOSTREAM_TYPE_RERNDERER} or {@link #AUDIOSTREAM_TYPE_CAPTURER}
    /// @return {@link #AUDIOSTREAM_SUCCESS} or an undesired error.
    pub fn OH_AudioStreamBuilder_Create(
        builder: *mut *mut OhAudioStreamBuilder,
        type_: OhAudioStreamType,
    ) -> OhAudioStreamResult;
    /// Destroy a streamBulder.
    ///
    ///  This function must be called when you are done using the builder.
    ///
    /// @since 10
    ///
    /// @param builder Reference provided by OH_AudioStreamBuilder_Create()
    /// @return {@link #AUDIOSTREAM_SUCCESS} or au undesired error.
    pub fn OH_AudioStreamBuilder_Destroy(builder: *mut OhAudioStreamBuilder)
        -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_SetSamplingRate(
        builder: *mut OhAudioStreamBuilder,
        rate: i32,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_SetChannelCount(
        builder: *mut OhAudioStreamBuilder,
        channelCount: i32,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_SetSampleFormat(
        builder: *mut OhAudioStreamBuilder,
        format: OhAudioStreamSampleFormat,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_SetEncodingType(
        builder: *mut OhAudioStreamBuilder,
        encodingType: OhAudioStreamEncodingType,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_SetLatencyMode(
        builder: *mut OhAudioStreamBuilder,
        latencyMode: OhAudioStreamLatencyMode,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_SetRendererInfo(
        builder: *mut OhAudioStreamBuilder,
        usage: OhAudioStreamUsage,
        content: OhAudioStreamContent,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_SetCapturerInfo(
        builder: *mut OhAudioStreamBuilder,
        sourceType: OHAudioStreamSourceType,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_SetRendererCallback(
        builder: *mut OhAudioStreamBuilder,
        callbacks: OhAudioRendererCallbacks,
        userData: *mut ::std::os::raw::c_void,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_SetCapturerCallback(
        builder: *mut OhAudioStreamBuilder,
        callbacks: OhAudioCapturerCallbacks,
        userdata: *mut ::std::os::raw::c_void,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_GenerateRenderer(
        builder: *mut OhAudioStreamBuilder,
        audioRenderer: *mut *mut OhAudioRenderer,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioStreamBuilder_GenerateCapturer(
        builder: *mut OhAudioStreamBuilder,
        audioCapturer: *mut *mut OhAudioCapturer,
    ) -> OhAudioStreamResult;
    pub fn OH_AudioCapturer_Start(capturer: *mut OhAudioCapturer) -> OhAudioStreamResult;
    pub fn OH_AudioCapturer_Release(capturer: *mut OhAudioCapturer) -> OhAudioStreamResult;
    pub fn OH_AudioCapturer_Stop(capturer: *mut OhAudioCapturer) -> OhAudioStreamResult;
}
